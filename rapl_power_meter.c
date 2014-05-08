/*
 * rapl_power_meter.c: RAPL power meter using powercap sysfs
 *
 * Copyright (C) 2014 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 or later as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author Name <Srinivas.Pandruvada@linux.intel.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <getopt.h>
#include <errno.h>
#include "index_html.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define STATUS_ERROR	-1
#define STATUS_SUCCESS	0

#define DEFAULT_PORT		9999
#define LISTEN_SIZE_QUEUE	10
#define MAX_BUFFER_SIZE		1024
#define MAX_HOST_NAME           64

#define	MAX_METHOD_SIZE		5
#define MAX_URI_SIZE		100
#define	MAX_VERSION_SIZE	4
#define MAX_PATH_NAME		128

static int local_port_id = DEFAULT_PORT;
static int pid_file_handle;
static char local_ip_addr[16];
static char local_host_name[MAX_HOST_NAME + 1];
static char local_index_html_file[MAX_PATH_NAME + 1];
static int local_index_html;

static int server_fd;
static struct sockaddr_in server_addr;

int send_error(FILE *fp, char *reason, char *err_str, char *short_msg,
		char *long_msg)
{
	int ret;

	ret = fprintf(fp, "HTTP/1.1 %s %s\n", err_str, short_msg);
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-type: text/html\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "\r\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "<html><title>RAPL Power Meter</title>");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "<body>\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "%s: %s\n", err_str, short_msg);
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "<p>%s: %s\r\n", long_msg, reason);
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "</body> </html>\r\n");
	if (ret < 0)
		goto err_ret;
	fflush(fp);
	
	return 0;
err_ret:
	return ret;
}

int send_success_response_plain(FILE *fp, char *response)
{
	int ret;

	ret = fprintf(fp, "HTTP/1.1 200 OK\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Server: RAPL Power Meter Server\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Access-Control-Allow-Origin: *\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-length: %d\n", (int)strlen(response));
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-type: text/plain\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "\r\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "%s\n", response);
	if (ret < 0)
		goto err_ret;
	fflush(fp);

	return 0;
err_ret:
	return ret;
}

int send_success_response(FILE *fp, char *response)
{
	char buffer[MAX_BUFFER_SIZE];
	int n;
	int ret;

	n = snprintf(buffer, MAX_BUFFER_SIZE, "%s",
		"<html><title>RAPL Power Meter</title>");
	n += snprintf(&buffer[n], MAX_BUFFER_SIZE - n, "%s",
		"<body bgcolor=" "ffffff" ">\n");
	n += snprintf(&buffer[n], MAX_BUFFER_SIZE - n, "%s",
		response);
	n += snprintf(&buffer[n], MAX_BUFFER_SIZE - n, "%s",
		"</body> </html>\r\n");

	ret = fprintf(fp, "HTTP/1.1 200 OK\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Server: RAPL Power Meter Server\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Access-Control-Allow-Origin: *\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-length: %d\n", (int)strlen(buffer));
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-type: text/html\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "\r\n");
	if (ret < 0)
		goto err_ret;
	fprintf(fp, "%s\n", buffer);
	fflush(fp);

	return 0;
err_ret:
	return ret;
}

int send_success(FILE *fp, int length)
{
	int ret;

	ret = fprintf(fp, "HTTP/1.1 200 OK\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Server: RAPL Power Meter Server\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Access-Control-Allow-Origin: *\n");
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-length: %d\n", length);
	if (ret < 0)
		goto err_ret;
	ret = fprintf(fp, "Content-type: text/html\n");
	if (ret < 0)
		goto err_ret;
	fprintf(fp, "\r\n");
	fflush(fp);

	return 0;
err_ret:
	return ret;
}

int powercap_sysfs_read(const char *path, char *buf, int len)
{
	int fd;
	int ret = 0;

	if (!buf || !len)
		return -EINVAL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = read(fd, buf, len);
	if (ret > 0 && ret < len)
		buf[ret] = '\0';
	close(fd);
	buf[len - 1] = '\0';

	return ret;
}

int powercap_get_rapl_domain_count(char *command)
{
	DIR *dir;
	struct dirent *entry;
	char *base_path = "/sys/class/powercap/";
	int count = 0;
	char buffer[64];
	int domain_id;
	char buffer_path[64];
	char *pch;

	domain_id = -1;

	/* extract domain id */
	pch = strtok(command, "/");
	if (pch) {
		pch = strtok(NULL, "/");
		if (pch)
			domain_id = atoi(pch);
	}
	if (domain_id != -1) {
		snprintf(buffer_path, sizeof(buffer_path), "%sintel-rapl:%d/",
							 base_path, domain_id);
	} else {
		strncpy(buffer_path, base_path, sizeof(buffer_path) - 1);
		buffer_path[sizeof(buffer_path) - 1] = '\0';
	}

	dir = opendir(buffer_path);
	if (dir != NULL) {
		entry = readdir(dir);
		while (entry != NULL) {
			if (domain_id == -1)
				snprintf(buffer, sizeof(buffer),
						"intel-rapl:%d", count);
			else
				snprintf(buffer, sizeof(buffer),
					"intel-rapl:%d:%d", domain_id, count);
			if (!strncmp(entry->d_name, buffer, strlen(buffer)))
				count++;
			entry = readdir(dir);
		}
		closedir(dir);
	}

	return count;
}

int read_domain_name(char *command, int name_buffer_size, char *name_buffer)
{
	int domain_id;
	int sub_domain_id;
	char *pch;
	char buffer[64];
	int ret;

	domain_id = -1;
	sub_domain_id = -1;

	/* extract domain id */
	pch = strtok(command, "/");
	if (pch) {
		pch = strtok(NULL, "/");
		if (pch) {
			domain_id = atoi(pch);
			pch = strtok(NULL, "/");
			if (pch)
				sub_domain_id = atoi(pch);
		}
	}

	if (domain_id == -1)
		return STATUS_ERROR;
	if (sub_domain_id == -1)
		snprintf(buffer, sizeof(buffer),
			"/sys/class/powercap/intel-rapl:%d/name", domain_id);
	else
		snprintf(buffer, sizeof(buffer),
		"/sys/class/powercap/intel-rapl:%d/intel-rapl:%d:%d/name",
					domain_id, domain_id, sub_domain_id);

	ret = powercap_sysfs_read(buffer, name_buffer, name_buffer_size);
	if (ret <= 0)
		return STATUS_ERROR;

	return STATUS_SUCCESS;
}

int read_domain_energy(char *command, int buffer_size, char *resp_buffer)
{
	int domain_id;
	int sub_domain_id;
	char *pch;
	char buffer[64];
	int ret;

	domain_id = -1;
	sub_domain_id = -1;

	/* extract domain id */
	pch = strtok(command, "/");
	if (pch) {
		pch = strtok(NULL, "/");
		if (pch) {
			domain_id = atoi(pch);
			pch = strtok(NULL, "/");
			if (pch)
				sub_domain_id = atoi(pch);
		}
	}
	if (domain_id == -1)
		return STATUS_ERROR;
	if (sub_domain_id == -1)
		snprintf(buffer, sizeof(buffer),
			"/sys/class/powercap/intel-rapl:%d/energy_uj",
				domain_id);
	else
		snprintf(buffer, sizeof(buffer),
		"/sys/class/powercap/intel-rapl:%d/intel-rapl:%d:%d/energy_uj",
				domain_id, domain_id, sub_domain_id);

	ret = powercap_sysfs_read(buffer, resp_buffer,  buffer_size);
	if (ret <= 0)
		return STATUS_ERROR;

	return STATUS_SUCCESS;

}

int read_domain_max_energy(char *command, int name_buffer_size,
						char *name_buffer)
{
	int domain_id;
	int sub_domain_id;
	char *pch;
	char buffer[128];
	int ret;

	domain_id = -1;
	sub_domain_id = -1;

	/* extract domain id */
	pch = strtok(command, "/");
	if (pch) {
		pch = strtok(NULL, "/");
		if (pch) {
			domain_id = atoi(pch);
			pch = strtok(NULL, "/");
			if (pch)
				sub_domain_id = atoi(pch);
		}
	}

	if (domain_id == -1)
		return STATUS_ERROR;
	if (sub_domain_id == -1)
		snprintf(buffer, sizeof(buffer),
		"/sys/class/powercap/intel-rapl:%d/max_energy_range_uj",
					domain_id);
	else
		snprintf(buffer, sizeof(buffer),
		"/sys/class/powercap/intel-rapl:%d/intel-rapl:%d:%d/max_energy_range_uj",
					domain_id, domain_id, sub_domain_id);
	printf("max energy read path %s\n", buffer);
	ret = powercap_sysfs_read(buffer, name_buffer, name_buffer_size);
	if (ret <= 0)
		return STATUS_ERROR;

	return STATUS_SUCCESS;
}

int process_cmd(FILE *fp, char *command, int buffer_size, char *buffer)
{
	if (!strcmp(command, "/rapl_domains_count") ||
		!strncmp(command, "/rapl_domains_count/",
			strlen("/rapl_domains_count/"))) {
		int count;
		count = powercap_get_rapl_domain_count(command);
		printf("rapl domain count %d\n", count);
		snprintf(buffer, buffer_size, "%d", count);
		send_success_response_plain(fp, buffer);
	} else if (!strncmp(command, "/rapl_domain_name/",
			strlen("/rapl_domain_name/"))) {
		if (read_domain_name(command, buffer_size, buffer) ==
							STATUS_SUCCESS)
			send_success_response_plain(fp, buffer);
		else
			send_error(fp, "Sysfs error", "500",
				"sysfs read error", "name read failed");
	} else if (!strncmp(command, "/rapl_domain_energy/",
			strlen("/rapl_domain_energy/"))) {
		if (read_domain_energy(command, buffer_size, buffer) ==
							STATUS_SUCCESS)
			send_success_response_plain(fp, buffer);
		else
			send_error(fp, "Sysfs error", "500",
				"sysfs read error", "energy read failed");
	} else if (!strncmp(command, "/rapl_domain_max_energy/",
			strlen("/rapl_domain_max_energy/"))) {
		if (read_domain_max_energy(command, buffer_size, buffer) ==
							STATUS_SUCCESS)
			send_success_response_plain(fp, buffer);
		else
			send_error(fp, "Sysfs error", "500",
				"sysfs read error", "energy read failed");
	} else if (!strcmp(command, "/") || !strcmp(command, "/index.html")) {
		int content_len;
		char local_ip_buffer[128];
		if (local_host_name[0] != '\0')
			content_len = snprintf(local_ip_buffer,
					sizeof(local_ip_buffer),
					"var root_path = 'http://%s:%d/';\n",
					local_host_name, local_port_id);
		else
			content_len = snprintf(local_ip_buffer,
					sizeof(local_ip_buffer),
					"var root_path = 'http://%s:%d/';\n",
					local_ip_addr, local_port_id);
		if (local_index_html) {
			FILE *src_fp;
			int size;
			int ch;
			src_fp = fopen(local_index_html_file, "r");
			if (!src_fp) {
				send_error(fp, "Page not found", "404",
				"Not found", "Requested URI not found");
				return TRUE;
			}
			fseek(src_fp, 0L, SEEK_END);
			size = ftell(src_fp);
			fseek(src_fp, 0L, SEEK_SET);
			send_success(fp, size);
			while(!feof(src_fp)) {
				ch = fgetc(src_fp);
				fputc(ch, fp);
			}
			fclose(src_fp);
		} else {
			content_len += strlen(index_html_contents_header);
			content_len += strlen(index_html_contents_contents);
			send_success(fp, content_len);
			fprintf(fp, "%s\n", index_html_contents_header);
			fprintf(fp, "%s\n", local_ip_buffer);
			fprintf(fp, "%s\n", index_html_contents_contents);
		}
	 } else if (!strncmp(command, "/terminate",
			strlen("/terminate"))) {
		return FALSE;
	} else {
		send_error(fp, "Page not found", "404",
				"Not found", "Requested URI not found");
	}

	return TRUE;
}

static int get_ip_address(char *interface, char *ip_address)
{
	struct ifaddrs *if_addr, *ifa;
	struct sockaddr_in *sa;
	char *addr;

	getifaddrs(&if_addr);
	for (ifa = if_addr; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);
			if (!strcmp(interface, ifa->ifa_name)) {
				strcpy(ip_address, addr);
				freeifaddrs(if_addr);
				fprintf(stdout,
				"Bind to Interface: %s\tAddress: %s:%d\n",
					ifa->ifa_name, addr, local_port_id);
				return STATUS_SUCCESS;
			}
		}
	}

	freeifaddrs(if_addr);
	return STATUS_ERROR;
}

static int init_tcp(char *interface)
{
	int opt_val;

	if (interface) {
		if (get_ip_address(interface, local_ip_addr) !=
						STATUS_SUCCESS) {
			fprintf(stderr,
				"get_ip_address for interface failed\n");
			return STATUS_ERROR;
		}
	}

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("error socket open");
		return STATUS_ERROR;
	}

	opt_val = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
					(const void *) &opt_val,
					sizeof(int));

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if (interface)
		server_addr.sin_addr.s_addr  = inet_addr(local_ip_addr);
	else
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons((unsigned short) local_port_id);
	if (bind(server_fd, (struct sockaddr *) &server_addr,
					sizeof(server_addr)) < 0) {
		perror("error in bind");
		goto err_close;
	}

	if (listen(server_fd, LISTEN_SIZE_QUEUE) < 0) {
		perror("error in listen");
		goto err_close;
	}

	return STATUS_SUCCESS;

err_close:
	close(server_fd);

	return STATUS_ERROR;
}

static void flush_request_buffer(FILE *fp)
{
	char buffer[MAX_BUFFER_SIZE];

	while (fgets(buffer, sizeof(buffer), fp)) {
		if (!strncmp(buffer, "\r\n", 2))
			break;
	}
}

static void set_socket_timeout(int sockfd)
{
	struct timeval timeout;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		perror("setsockopt failed\n");

	if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		perror("setsockopt failed\n");
}

static int start_server(char *interface)
{
	struct sockaddr_in client_addr;
	socklen_t client_len;
	int client_fd;
	char *client_ip_addr;
	struct hostent *client_host;
	FILE *fp;
	char *buffer;
	char *uri;
	char *method;
	int continue_proc = TRUE;

	if (init_tcp(interface) < 0) {
		fprintf(stderr, "init TCP failed\n");
		return STATUS_ERROR;
	}

	if (!interface)
		strcpy(local_ip_addr, "localhost");

	client_len = sizeof(client_addr);
	while (continue_proc) {
		client_fd = accept(server_fd, (struct sockaddr *) &client_addr,
				&client_len);
		if (client_fd < 0) {
			perror("errorn in accept");
			continue;
		}
		client_host = gethostbyaddr(
				(const char *) &client_addr.sin_addr.s_addr,
				sizeof(client_addr.sin_addr.s_addr), AF_INET);
		if (client_host == NULL) {
			perror("error in gethostbyaddr");
			/* No need to bail out */
		}

		client_ip_addr = inet_ntoa(client_addr.sin_addr);
		if (client_ip_addr == NULL) {
			perror("Can't get client IP\n");
			close(client_fd);
			continue;
		}
		set_socket_timeout(client_fd);
		fprintf(stdout, "Received Request from %s\n", client_ip_addr);
		fp = fdopen(client_fd, "r+");
		if (fp == NULL) {
			perror("error in fdopen");
			close(client_fd);
			continue;
		}
		buffer = malloc(MAX_BUFFER_SIZE);
		if (!buffer) {
			perror("error in malloc");
			fclose(fp);
			close(client_fd);
			continue;
		}
		if (fgets(buffer, MAX_BUFFER_SIZE, fp) == NULL)
			goto continue_loop;

		uri = NULL;
		method = NULL;

		method = strtok(buffer, " ");
		if (!method) {
			flush_request_buffer(fp);
			send_error(fp, "none", "400", "Bad request",
				"unknown method");
			goto continue_loop;
		}

		if (strncasecmp(method, "GET", 3)) {
			flush_request_buffer(fp);
			send_error(fp, method, "501", "Not Implemented",
				"Only GET is supported");
			goto continue_loop;
		}
		uri = strtok(NULL, " ");
		if (!uri) {
			flush_request_buffer(fp);
			send_error(fp, method, "400", "Bad request",
				"Bad request");
			goto continue_loop;
		}
		flush_request_buffer(fp);

		if (!process_cmd(fp, uri, MAX_BUFFER_SIZE, buffer))
			continue_proc = FALSE;
		fprintf(stdout, "processing done\n");

continue_loop:
		free(buffer);
		fclose(fp);
		close(client_fd);
	}

	return STATUS_SUCCESS;
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		close(server_fd);
		exit(STATUS_SUCCESS);
		break;
	default:
		break;
	}
}

static void daemonize(char *rundir, char *pidfile)
{
	int pid, sid, i;
	char str[10];
	struct sigaction sig_actions;
	sigset_t sig_set;

	if (getppid() == 1)
		return;

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGCHLD);
	sigaddset(&sig_set, SIGTSTP);
	sigaddset(&sig_set, SIGTTOU);
	sigaddset(&sig_set, SIGTTIN);
	sigprocmask(SIG_BLOCK, &sig_set, NULL);

	sig_actions.sa_handler = signal_handler;
	sigemptyset(&sig_actions.sa_mask);
	sig_actions.sa_flags = 0;

	sigaction(SIGHUP, &sig_actions, NULL);
	sigaction(SIGTERM, &sig_actions, NULL);
	sigaction(SIGINT, &sig_actions, NULL);

	pid = fork();
	if (pid < 0) {
		/* Could not fork */
		exit(EXIT_FAILURE);
	}
	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(027);

	sid = setsid();
	if (sid < 0)
		exit(EXIT_FAILURE);

	/* close all descriptors */
	for (i = getdtablesize(); i >= 0; --i)
		close(i);

 	i = open("/dev/null", O_RDWR);
	dup(i);
	dup(i);

	chdir(rundir);

	pid_file_handle = open(pidfile, O_RDWR | O_CREAT, 0600);
	if (pid_file_handle == -1) {
		/* Couldn't open lock file */
		exit(1);
	}
	/* Try to lock file */
#ifdef LOCKF_SUPPORT
	if (lockf(pid_file_handle, F_TLOCK, 0) == -1) {
#else
	if (flock(pid_file_handle, LOCK_EX|LOCK_NB) < 0) {
#endif
		/* Couldn't get lock on lock file */
		fprintf(stderr, "Couldn't get lock file %d\n", getpid());
		exit(1);
	}
	snprintf(str, sizeof(str), "%d\n", getpid());
	write(pid_file_handle, str, strlen(str));
	close(i);
}

static void print_usage(FILE *stream, int exit_code)
{
	fprintf(stream, "Usage:  rapl_power_meter [ ... ]\n");
	fprintf(stream, "  --help Display this usage information.\n"
			"  --version Show version.\n"
			"  --no-daemon No daemon.\n"
			"  --interface\n"
			"  --hostname\n"
			"  --index.html specify local index.html path\n"
			"  --port\n");
	exit(exit_code);
}

int main(int argc, char *argv[])
{
	int c;
	int option_index = 0;
	int no_daemon = 0;
	char interface[20];
	int def_interface = 1;
	int ret;

	const char *short_options = "hvni:p:o:";
	static struct option long_options[] = {
			{ "help", no_argument, 0, 'h' },
			{ "version", no_argument, 0, 'v' },
			{ "no-daemon", no_argument, 0, 'n' },
			{ "interface", required_argument, 0, 'i'},
			{ "hostname", required_argument, 0, 'o'},
			{ "port", required_argument, 0, 'p'},
			{ "index.html", required_argument, 0, 'x'},
			{ NULL, 0, NULL, 0 } };

	if (argc > 1) {
		while ((c = getopt_long(argc, argv, short_options,
				long_options,
				&option_index)) != -1) {
			switch (c) {
			case 'h':
				print_usage(stdout, 0);
				break;
			case 'v':
				fprintf(stdout, "1.0\n");
				exit(0);
				break;
			case 'n':
				no_daemon = 1;
				break;
			case 'i':
				strncpy(interface, optarg,
						sizeof(interface) - 1);
				interface[sizeof(interface) - 1] = '\0';
				def_interface = 0;
				break;
			case 'p':
				local_port_id = atoi(optarg);
				break;
			case 'o':
				strncpy(local_host_name, optarg, MAX_HOST_NAME);
				break;
			case 'x':
				strncpy(local_index_html_file, optarg, MAX_PATH_NAME);
				local_index_html = 1;
				break;
			case -1:
			case 0:
				break;
			default:
				break;
			}
		}
	}
	signal(SIGPIPE, SIG_IGN);
	if (!no_daemon)
		daemonize((char *) "/tmp/",
				(char *)"/tmp/rapl_power_meter.pid");
	else
		signal(SIGINT, signal_handler);

	if (def_interface)
		ret = start_server(NULL);
	else
		ret = start_server(interface);

	if (ret != STATUS_SUCCESS)
		fprintf(stderr, "Start server Failed\n");

	return 0;
}
