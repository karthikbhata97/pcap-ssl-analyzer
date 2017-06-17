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
