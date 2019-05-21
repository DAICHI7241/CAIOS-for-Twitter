#pragma once

#include <sstream>
#include <fstream>
#include <vector>
#include <locale>
#include <winstring.h>
#include <algorithm>
#include <iomanip>
#include <queue>
#include <time.h>
#include <cpprest/http_client.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#pragma comment(lib,"libeay32.lib") 

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::client;

#define REST_POST_PATH "jsonファイルの出力先"
#define REST_GET_PATH "jsonファイルの出力先"
#define TWITTER_URL "https://api.twitter.com/1.1/statuses/update.json"

typedef enum {
	POST,
	GET
} METHOD;

enum CodePageID : unsigned int {
	ANSI = CP_ACP,	// ANSI
	OEM = CP_OEMCP,	// OEM(依存)
	MAC = CP_MACCP,	// MAC
	UTF7 = CP_UTF7,	// UTF-7
	UTF8 = CP_UTF8	// UTF-8
};

struct Request {
	string url;
	string post;
};

struct TwitterAPI_Keys {
	string Consumer_Key = "ここにキーを代入";
	string Consumer_Sec = "ここにキーを代入";
	string Accesstoken = "ここにキーを代入";
	string Accesstoken_Aec = "ここにキーを代入";
};

namespace CAIOS {

	namespace String {

		static string UTF8_to_SJIS(string message) {
			int n;
			wchar_t ucs2[1000];
			char utf8[1000];
			n = MultiByteToWideChar(CP_UTF8, 0, message.c_str(), message.size(), ucs2, 1000);
			n = WideCharToMultiByte(CP_ACP, 0, ucs2, n, utf8, 1000, 0, 0);
			return std::string(utf8, n);
		}

		static string SJIS_to_UTF8(std::string const& message)		{
			int n;
			wchar_t ucs2[1000];
			char utf8[1000];
			n = MultiByteToWideChar(CP_ACP, 0, message.c_str(), message.size(), ucs2, 1000);
			n = WideCharToMultiByte(CP_UTF8, 0, ucs2, n, utf8, 1000, 0, 0);
			return std::string(utf8, n);
		}

		// string から wstring 変換
		static wstring StringToWString(const string& refSrc, unsigned int codePage = CodePageID::ANSI) {
			vector<wchar_t> buffer(MultiByteToWideChar(codePage, 0, refSrc.c_str(), -1, nullptr, 0));
			MultiByteToWideChar(codePage, 0, refSrc.c_str(), -1, &buffer.front(), buffer.size());
			return wstring(buffer.begin(), buffer.end());
		}

		// wstring から string 変換
		static string WStringToString(const wstring& refSrc, unsigned int codePage = CodePageID::OEM) {
			vector<char> buffer(WideCharToMultiByte(codePage, 0, refSrc.c_str(), -1, nullptr, 0, nullptr, nullptr));
			WideCharToMultiByte(codePage, 0, refSrc.c_str(), -1, &buffer.front(), buffer.size(), nullptr, nullptr);
			return string(buffer.begin(), buffer.end());
		}

		static string EraseString(string str, string erase) {
			for (size_t c = str.find_first_of(erase); c != string::npos; c = c = str.find_first_of(erase)) {
				str.erase(c, 1);
			}
			return str;
		}
	}

	namespace REST {

		static string GET(Request req) {
			try {
				using namespace CAIOS::String;

				http_client client(StringToWString(req.url));

				cout << " -> HTTP request mode [POST]" << endl;
				cout << " -> HTTP request to " << req.url << endl;

				auto response = client.request(methods::GET).get();
				auto str = response.extract_string();

				cout << " -> Server returned returned status code " << response.status_code() << '.' << endl;
				cout << " -> Content length is " << response.headers().content_length() << " bytes.\n" << endl;

				ofstream ofs(REST_POST_PATH);
				ofs << WStringToString(str.get().c_str()) << endl;
				ofs.close();

				return WStringToString(str.get().c_str());
			}
			catch (...) {
				cout << "HTTP通信中に例外が発生しました　[GET]" << endl;
			}
		}

		static string POST(Request req) {
			try {
				using namespace CAIOS::String;

				http_client client(StringToWString(req.url));

				http_request request(methods::POST);

				cout << " -> HTTP request mode [POST]" << endl;
				cout << " -> HTTP request to " << req.url << endl;

				char body[3000];

				request.headers().add(L"Content-Type", L"application/x-www-form-urlencoded");
				request.set_body(req.post);

				auto response = client.request(request).get();
				auto str = response.extract_string();

				cout << " -> Server returned returned status code " << response.status_code() << '.' << endl;
				cout << " -> Content length is " << response.headers().content_length() << " bytes.\n" << endl;

				ofstream ofs(REST_POST_PATH);
				ofs << WStringToString(str.get().c_str()) << endl;
				ofs.close();

				return WStringToString(str.get().c_str());
			}
			catch (...) {
				cout << "HTTP通信中に例外が発生しました　[POST]" << endl;
			}
		}

		static string URL_encode(string str) {
			const int NUM_BEGIN_UTF8 = 48;
			const int CAPITAL_BEGIN_UTF8 = 65;
			const int LOWER_BEGIN_UTF8 = 97;

			int charCode = -1;
			string encoded;
			stringstream out;

			for (int i = 0; str[i] != 0; i++) {
				charCode = (int)(unsigned char)str[i];

				//エンコードする必要の無い文字の判定
				if ((NUM_BEGIN_UTF8 <= charCode && charCode <= NUM_BEGIN_UTF8 + 9)
					|| (CAPITAL_BEGIN_UTF8 <= charCode && charCode <= CAPITAL_BEGIN_UTF8 + 25)
					|| (LOWER_BEGIN_UTF8 <= charCode && charCode <= LOWER_BEGIN_UTF8 + 25)
					|| str[i] == '.' || str[i] == '_' || str[i] == '-' || str[i] == '~'){
					out << str[i];
				}
				else {
					out << '%' << hex << uppercase << charCode;
				}
			}
			encoded = out.str();
			return encoded;
		}
	}

	namespace Twitter {
		namespace OAuth {
			static string CreateData(vector<string>const OAuth, METHOD method, int Start) {
				string query;
				for (int t = Start; t < OAuth.size(); t++) {
					if (t != Start)query += "&";
					query += OAuth[t];
				}
				return query;
			}

			static int split_url(const string url, vector<string>* OAuth) {
				int num = url.find_first_of('?');
				OAuth->push_back(url.substr(0, num));
				OAuth->push_back(url.substr(num + 1));
				return 0;
			}

			static string sha1(const string Key, const string Data) {
				char* key = (char*)Key.c_str();
				char* data = (char*)Data.c_str();
				unsigned char res[SHA_DIGEST_LENGTH + 1];
				size_t reslen;

				HMAC(EVP_sha1(), key, strlen(key), reinterpret_cast<const unsigned char*>(data), strlen(data), res, &reslen);

				return string(reinterpret_cast<char*>(res), reslen);
			}

			static int encode_base64(char* bufin, int len, char* bufout){
				static unsigned char base64[] =	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
				unsigned char* pin = (unsigned char*)bufin;
				unsigned char* pout = (unsigned char*)bufout;

				for (int i = 0; i < len - 2; i += 3){
					*pout++ = base64[pin[0] >> 2];
					*pout++ = base64[0x3F & ((pin[0] << 4) | (pin[1] >> 4))];
					*pout++ = base64[0x3F & ((pin[1] << 2) | (pin[2] >> 6))];
					*pout++ = base64[0x3F & pin[2]];
					pin += 3;
				}
				if (len % 3 == 1){
					*pout++ = base64[pin[0] >> 2];
					*pout++ = base64[0x3F & (pin[0] << 4)];
					*pout++ = '=';
					*pout++ = '=';
				}
				else if (len % 3 == 2){
					*pout++ = base64[pin[0] >> 2];
					*pout++ = base64[0x3F & ((pin[0] << 4) | (pin[1] >> 4))];
					*pout++ = base64[0x3F & (pin[1] << 2)];
					*pout++ = '=';
				}
				*pout = '\0';
				return pout - (unsigned char*)bufout;
			}

			static string CreateSignature(string ConsumerSecret, string AccessSecret, vector<string>const& OAuth, METHOD method, int Start = 1) {
				string str, key, data, methods;
				char out[256];

				if (method == POST)methods = "POST";
				else methods = "GET";

				key = CAIOS::REST::URL_encode(ConsumerSecret) + "&" + CAIOS::REST::URL_encode(AccessSecret);

				data = methods + "&" + CAIOS::REST::URL_encode(OAuth[0]) + "&" + CAIOS::REST::URL_encode(CreateData(OAuth, method, Start));

				str = sha1(key, data);

				CAIOS::Twitter::OAuth::encode_base64((char*)str.c_str(), str.size(), out);

				return CAIOS::REST::URL_encode(out);
			}

			static int IntOAuthParams(vector<string>* OAuth, METHOD method) {
				TwitterAPI_Keys key;

				auto CreateNonce = []() {
					static const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
					const unsigned int max = 26 + 26 + 10 + 1;
					char tmp[50];
					srand((unsigned int)time(0));
					int len = 15 + rand() % 16;
					for (int i = 0; i < len; i++) {
						tmp[i] = chars[rand() % max];
					}
					return std::string(tmp, len);
				};

				string oauth_nonce = "oauth_nonce";
				oauth_nonce += "=";
				oauth_nonce += CreateNonce();
				OAuth->push_back(oauth_nonce);

				string oauth_timestamp = "oauth_timestamp";
				oauth_timestamp += "=";
				oauth_timestamp += to_string((int)time(nullptr));
				OAuth->push_back(oauth_timestamp);

				string oauth_token = "oauth_token";
				oauth_token += "=";
				oauth_token += key.Accesstoken;
				OAuth->push_back(oauth_token);

				string oauth_consumer_key = "oauth_consumer_key";
				oauth_consumer_key += "=";
				oauth_consumer_key += key.Consumer_Key;
				OAuth->push_back(oauth_consumer_key);

				string oauth_signature_method = "oauth_signature_method";
				oauth_signature_method += "=";
				oauth_signature_method += "HMAC-SHA1";
				OAuth->push_back(oauth_signature_method);

				string oauth_version = "oauth_version";
				oauth_version += "=";
				oauth_version += "1.0";
				OAuth->push_back(oauth_version);

				sort(OAuth->begin() + 1, OAuth->end());

				string oauth_signature = "oauth_signature";
				oauth_signature += "=";
				oauth_signature += CreateSignature(key.Consumer_Sec, key.Accesstoken_Aec, *OAuth, method);
				OAuth->push_back(oauth_signature);

				return 0;
			}

			static Request OAuthAuthentication(string url, METHOD method) {
				vector<string> OAuth;

				split_url(url, &OAuth);

				CAIOS::Twitter::OAuth::IntOAuthParams(&OAuth, method);

				Request req;

				if (method == POST) {
					req.url = OAuth[0];
					req.post = CAIOS::Twitter::OAuth::CreateData(OAuth, method, 1);
				}
				else {
					req.url = OAuth[0];
					req.post = CAIOS::Twitter::OAuth::CreateData(OAuth, method, 1);
				}

				return req;
			}
		}

		static string tweet(string message) {
			message = CAIOS::String::SJIS_to_UTF8(message);

			string url = TWITTER_URL;
			url += "?status=" + CAIOS::REST::URL_encode(message);

			Request req = OAuth::OAuthAuthentication(url, POST);
			return CAIOS::REST::POST(req);
		}
	}
}