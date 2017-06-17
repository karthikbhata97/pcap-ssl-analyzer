#include<iostream>
using namespace std;

int print_alert(short int);

int print_alert(short int description) {
  switch (description) {
    case 0:
          cout<<"close_notify"<<endl;
          break;
    case 10:
          cout<<"unexpected_message"<<endl;
          break;
    case 20:
          cout<<"bad_record_mac"<<endl;
          break;
    case 21:
          cout<<"decryption_failed_RESERVED"<<endl;
          break;
    case 22:
          cout<<"record_overflow"<<endl;
          break;
    case 30:
          cout<<"decompression_failure"<<endl;
          break;
    case 40:
          cout<<"handshake_failure"<<endl;
          break;
    case 41:
          cout<<"no_certificate_RESERVED"<<endl;
          break;
    case 42:
          cout<<"bad_certificate"<<endl;
          break;
    case 43:
          cout<<"unsupported_certificate"<<endl;
          break;
    case 44:
          cout<<"certificate_revoked"<<endl;
          break;
    case 45:
          cout<<"certificate_expired"<<endl;
          break;
    case 46:
          cout<<"certificate_unknown"<<endl;
          break;
    case 47:
          cout<<"illegal_parameter"<<endl;
          break;
    case 48:
          cout<<"unknown_ca"<<endl;
          break;
    case 49:
          cout<<"access_denied"<<endl;
          break;
    case 50:
          cout<<"decode_error"<<endl;
          break;
    case 51:
          cout<<"decrypt_error"<<endl;
          break;
    case 60:
          cout<<"export_restriction_RESERVED"<<endl;
          break;
    case 70:
          cout<<"protocol_version"<<endl;
          break;
    case 71:
          cout<<"insufficient_security"<<endl;
          break;
    case 80:
          cout<<"internal_error"<<endl;
          break;
    case 90:
          cout<<"user_canceled"<<endl;
          break;
    case 100:
          cout<<"no_renegotiation"<<endl;
          break;
    case 110:
          cout<<"unsupported_extension"<<endl;
          break;
    default:
          return 0;
  }
  return 1;
}
