// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static io_context_t ctx;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *) p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the reply header. */

}


static enum resource_type connection_get_resource_type(struct connection *conn)
{
	/* TODO: Get resource type depending on request path/filename. Filename should
	 * point to the static or dynamic folder.
	 */
	return conn->res_type;
}


struct connection *connection_create(int sockfd)
{
	/* TODO: Initialize connection structure on given socket. */
	struct connection *connection_init = malloc(sizeof(struct connection));
	connection_init->sockfd = sockfd;
	memset(connection_init->recv_buffer, 0, BUFSIZ);
	memset(connection_init->send_buffer, 0, BUFSIZ);
	return connection_init;
}

void connection_start_async_io(struct connection *conn)
{
	/* TODO: Start asynchronous operation (read from file).
	 * Use io_submit(2) & friends for reading data asynchronously.
	 */
}

void connection_remove(struct connection *conn)
{
	/* TODO: Remove connection handler. */

	close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
//	free(conn);
}

void handle_new_connection(void)
{
	/* TODO: Handle a new connection request on the server socket. */
	socklen_t socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	/* TODO: Accept new connection. */
	int accepting_fd = accept(listenfd, (SSA *) (&addr), &socklen);
	/* TODO: Set socket to be non-blocking. */
	int flags = fcntl(accepting_fd, F_GETFL, 0);
	flags = flags | O_NONBLOCK;
	fcntl(accepting_fd, F_SETFL, flags);
	/* TODO: Instantiate new connection handler. */
	struct connection *conn = connection_create(accepting_fd);
	/* TODO: Add socket to epoll. */
	w_epoll_add_ptr_in(epollfd, accepting_fd, conn);
	/* TODO: Initialize HTTP_REQUEST parser. */
	http_parser parser;
	http_parser_init(&parser, HTTP_BOTH);
	conn->request_parser = parser;
	conn->request_parser.data = conn;
}

void receive_data(struct connection *conn)
{
	/* TODO: Receive message on socket.
	 * Store message in recv_buffer in struct connection.
	 */
	int bytes = 0;
	int old_bytes = 0;
//	char *old_buffer = malloc(BUFSIZ * sizeof(char));
//	old_buffer[0] = 0;
//	int i = 0;
	do {
//		memcpy(old_buffer, conn->recv_buffer, BUFSIZ * sizeof(char));
		bytes = recv(conn->sockfd, conn->recv_buffer + old_bytes, BUFSIZ - old_bytes, 0);
		// printf("RECV_BUFFER: %s\n", conn->recv_buffer);
		old_bytes += bytes;
//		i++;i
	} while (bytes > 0);

//	free(old_buffer);
	parse_header(conn);
	conn->recv_len = old_bytes;
}

int connection_send_data_custom_with_len(struct connection *conn, char *custom, size_t custom_len)
{
	/* May be used as a helper function. */
	/* TODO: Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */
	// printf("__ sending: %s\n", custom);
	int old_bytes = 0, bytes = 0;
	do {
		bytes = send(conn->sockfd, custom + old_bytes, custom_len - old_bytes, 0);
		old_bytes += bytes;
	} while (bytes > 0);
}


static void connection_prepare_send_404(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the 404 header. */
	char error[404] = "HTTP/1.0 404 NOT_OK";
	connection_send_data_custom_with_len(conn, error, strlen(error));
	return;
}


int connection_open_file(struct connection *conn)
{
	/* TODO: Open file and update connection fields. */
	// open file
	io_setup(1, &conn->ctx);

	char path[200] = "./";
	strcat(path, conn->request_path);

	int file_descriptor = open(path, O_RDWR);
	if (file_descriptor == -1) {
		connection_prepare_send_404(conn);
		return -1;
	}
	// printf("file_Desc: %d\n", file_descriptor);
	struct stat st;
	fstat(file_descriptor, &st);
	int size = st.st_size;
//	printf("size: %d\n", size);
	conn->file_size = size;
	return file_descriptor;
}

void connection_complete_async_io(struct connection *conn)
{
	/* TODO: Complete asynchronous operation; operation returns successfully.
	 * Prepare socket for sending.
	 */
}

int connection_send_data(struct connection *conn)
{
	/* May be used as a helper function. */
	/* TODO: Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */

	return connection_send_data_custom_with_len(conn, conn->send_buffer, conn->send_len);
}

int send_file_dyn(struct connection *conn, size_t *offset)
{
	int len = BUFSIZ > (conn->file_size - *offset) ? (conn->file_size - *offset) : BUFSIZ;
	char *custom = malloc(BUFSIZ * sizeof(char));
	memset(&conn->iocb, 0, sizeof(struct iocb));
	io_prep_pread(&conn->iocb, conn->fd, custom, len, *offset);
	conn->piocb[0] = &conn->iocb;
	io_submit(conn->ctx, 1, conn->piocb);

	struct io_event events[1];
	io_getevents(conn->ctx, 1, 1, events, NULL);
	if (events[0].res < 0) {
		return -1;
	}
	int bytes_send = send(conn->sockfd, custom, len, 0);
//	int bytes_send = connection_send_data_custom_with_len(conn, custom, len);
	if (bytes_send < 0) {
		free(custom);
		return -1;
	}

	(*offset) += bytes_send;
	(*offset) = (*offset) > conn->file_size ? conn->file_size : (*offset);

	free(custom);

	return 0;
}

int parse_header(struct connection *conn)
{
	/* TODO: Parse the HTTP header and extract the file path. */
	/* Use mostly null settings except for on_path callback. */
	http_parser_settings settings_on_path = {
			.on_message_begin = 0,
			.on_header_field = 0,
			.on_header_value = 0,
			.on_path = aws_on_path_cb,
			.on_url = 0,
			.on_fragment = 0,
			.on_query_string = 0,
			.on_body = 0,
			.on_headers_complete = 0,
			.on_message_complete = 0
	};
	w_epoll_update_fd_in(epollfd, conn->sockfd);

	int number_of_bytes = http_parser_execute(&(conn->request_parser), &settings_on_path, conn->recv_buffer, BUFSIZ);
	int fd = connection_open_file(conn);
	if (fd != -1) {
		conn->fd = fd;

		if (strstr(conn->request_path, "static") != NULL) {
			char header[100] = "HTTP/1.0 200 OK\r\n\r\n";
			connection_send_data_custom_with_len(conn, header, strlen(header));
			conn->file_pos = 0;
			while (conn->file_pos < conn->file_size) {
				int err = sendfile(conn->sockfd, conn->fd, &conn->file_pos, conn->file_size);
			}

			close(conn->fd);
		} else {
			printf("probing fhjhhjghfj dyn %zu,\n", conn->file_size);

			conn->file_pos = 0;
			while (conn->file_pos < conn->file_size) {
				int err = send_file_dyn(conn, &conn->file_pos);
			}

			close(conn->fd);
			io_destroy(conn->ctx);
			conn->file_pos = 0;
			conn->file_size = -1;

			printf("broke\n");

		}
	}

	w_epoll_remove_fd(epollfd, conn->sockfd);
	connection_remove(conn);
	return 0;
}


enum connection_state connection_send_static(struct connection *conn)
{
	/* TODO: Send static data using sendfile(2). */
	return STATE_NO_STATE;
}


int connection_send_dynamic(struct connection *conn)
{
	/* TODO: Read data asynchronously.
	 * Returns 0 on success and -1 on error.
	 */
	return 0;
}


void handle_input(struct connection *conn)
{
	/* TODO: Handle input information: may be a new message or notification of
	 * completion of an asynchronous I/O operation.
	 */

	switch (conn->state) {
		default:
			printf("shouldn't get here %d\n", conn->state);
	}
}

void handle_output(struct connection *conn)
{
	/* TODO: Handle output information: may be a new valid requests or notification of
	 * completion of an asynchronous I/O operation or invalid requests.
	 */

	switch (conn->state) {

		default:
			ERR("Unexpected state\n");
			exit(1);
	}
}

void handle_client(uint32_t event, struct connection *conn)
{
	/* TODO: Handle new client. There can be input and output connections.
	 * Take care of what happened at the end of a connection.
	 */
}

int main(void)
{
	int rc;

	/* TODO: Initialize asynchronous operations. */
	/* TODO: Initialize multiplexing. */

	/* TODO: Create server socket. */

	printf("hello hehe!\n");
	epollfd = w_epoll_create();
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);

	/* TODO: Add server socket to epoll object*/
	rc = w_epoll_add_fd_in(epollfd, listenfd);

	/* Uncomment the following line for debugging. */
	// dlog(LOG_INFO, "Server waiting for connections on port %d\n", AWS_LISTEN_PORT);

	/* server main loop */
	// printf("executing...\n");
	while (1) {
		struct epoll_event rev;

		/* TODO: Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);
//		printf("event: %d\n", rev.events);
		/* TODO: Switch event types; consider
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */
		if (rev.data.fd == listenfd) {
			// a new connection was made
			// printf("handling new connection\n");
			handle_new_connection();
		} else {
			// existing connection
			if (rev.events & EPOLLIN) {
//				 printf("receive new data...\n");
				receive_data(rev.data.ptr);

			}
			if (rev.events & EPOLLOUT) {
//				 printf("send new data\n");
				connection_send_data(rev.data.ptr);
			}
		}
	}


	return 0;
}
