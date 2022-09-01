#include "httpd.h"

#define PORT_DEFAULT "12913"

int main(int argc, const char **argv)
{
    const char *PORT;

    if (argc < 2) {
        PORT = PORT_DEFAULT;
    } else {
        PORT = argv[1];
    }

    fprintf(stderr, "port is %s.\n", PORT);
    
    serve_forever(PORT);
    return 0;
}

void route()
{
    ROUTE_START()

    ROUTE_GET("/")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("httpd_test_successful");
    }

    ROUTE_POST("/")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
        printf("Fetch the data using `payload` variable.");
    }
  
    ROUTE_END()
}
