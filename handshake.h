#include <iostream>
using namespace std;

int handshake_type(const u_char *);
void hello_request(const u_char *);
void client_hello(const u_char *);
void server_hello(const u_char *);
void certificate(const u_char *);
void server_key_exchange (const u_char *);
void certificate_request(const u_char *);
void server_hello_done(const u_char *);
void certificate_verify(const u_char *);
void client_key_exchange(const u_char *);
void finished(const u_char *);
void print_hex(const u_char *, int);


void print_hex(const u_char *data, int len) {
  int val;
  for(int i=0;i<len;i++) {
    val = *(int *)(data+i) & 0xFF;
    cout<< hex << val << dec;
  }
  cout<<endl;
}

int handshake_type(const u_char *body) {
  int type = *(int *)body & 0xFF;
  switch (type) {
    case 0:
    cout<<"hello_request"<<endl;
    hello_request(body);
    break;
    case 1:
    cout<<"client_hello"<<endl;
    client_hello(body);
    break;
    case 2:
    cout<<"server_hello"<<endl;
    server_hello(body);
    break;
    case 11:
    cout<<"certificate"<<endl;
    certificate(body);
    break;
    case 12:
    cout<<"server_key_exchange "<<endl;
    server_key_exchange (body);
    break;
    case 13:
    cout<<"certificate_request"<<endl;
    certificate_request(body);
    break;
    case 14:
    cout<<"server_hello_done"<<endl;
    server_hello_done(body);
    break;
    case 15:
    cout<<"certificate_verify"<<endl;
    certificate_verify(body);
    break;
    case 16:
    cout<<"client_key_exchange"<<endl;
    client_key_exchange(body);
    break;
    case 20:
    cout<<"finished"<<endl;
    finished(body);
    break;
    default:
    cout<<"Invalid"<<endl;
    return 0;
  }
  return 1;
}

void hello_request(const u_char *body)
{
  return;
}

void client_hello(const u_char *body)
{
  int a = (int)*(body+1); // second
  int b = (int)*(body+2); // third
  int c = (int)*(body+3); // furth byte
  int length = (a<<16) + (b<<8) + (c);
  cout<<"client hello length: "<<length<<endl;
  body = body + 4;
  short int version = *(short int *)(body);
  cout<<"Version: ";
  switch (version) {
    case 0x0300:
    cout<<"SSL 3.0"<<endl;
    break;
    case 0x0301:
    cout<<"TLS 1.1"<<endl;
    break;
    case 0x0302:
    cout<<"TLS 1.2"<<endl;
    break;
    case 0x0303:
    cout<<"TLS 1.3"<<endl;
    break;
    default:
    cout<<"failed to decode"<<endl;
    break;
  }
  body = body + 2;

  cout<<"Random: ";
  print_hex(body, 32);
  body = body + 32;

  int sid_len = (int)*body;
  cout<<"session id length: "<<(int)sid_len<<endl;
  body = body + 1;

  cout<<"session id: ";
  print_hex(body, sid_len);
  body = body + sid_len;

  short int ciphersuite_len = *(short int *)(body);
  ciphersuite_len = (ciphersuite_len>>8) | (ciphersuite_len<<8);
  cout<<"cipher suite length: "<<ciphersuite_len<<endl;
  body = body + 2;

  cout<<"follows.. "<<(ciphersuite_len/2)<<" suites"<<endl;
  body = body + ciphersuite_len;

  int compression_len = (int)*body;
  cout<<"compression method length: "<<endl;
  body = body + 1;

  int compression_method = (int)*body;
  cout<<"compression method: "<<compression_method<<"(null)"<<endl;
  body = body + compression_len;

  short int extenstions_len = *(short int*)body;
  extenstions_len = (extenstions_len>>8) | (extenstions_len<<8);
  cout<<"extenstions length: "<<extenstions_len<<endl;
  body = body + 2;

  cout<<"follows.. extenstions"<<endl;
  body = body + extenstions_len;

  return;
}

void server_hello(const u_char *body)
{
  return;
}

void certificate(const u_char *body)
{
  return;
}

void server_key_exchange (const u_char *body)
{
  return;
}

void certificate_request(const u_char *body)
{
  return;
}

void server_hello_done(const u_char *body)
{
  return;
}

void certificate_verify(const u_char *body)
{
  return;
}

void client_key_exchange(const u_char *body)
{
  return;
}

void finished(const u_char *body)
{
  return;
}
