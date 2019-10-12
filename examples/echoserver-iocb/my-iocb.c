/* my-iocb.c
 *
 * Copyright (C) 2014-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <wolfssh/ssh.h>

#include <examples/echoserver-iocb/my-iocb.h>

#include <sys/socket.h>
#include <sys/errno.h>

int my_IORecv(WOLFSSH *ssh, char *buff, int sz, void *ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int sockfd = *(int *)ctx;
    int recvd;
    (void)ssh;

    /* Receive message from socket */
    if ((recvd = (int)recv(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfssh terms */

        fprintf(stderr, "IO RECEIVE ERROR: ");
        switch (errno)
        {
        case EWOULDBLOCK:
            fprintf(stderr, "socket timeout\n");
            return WS_CBIO_ERR_TIMEOUT;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WS_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WS_CBIO_ERR_ISR;
        case ECONNREFUSED:
            fprintf(stderr, "connection refused\n");
            return WS_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            fprintf(stderr, "connection aborted\n");
            return WS_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WS_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0)
    {
        printf("Connection closed\n");
        return WS_CBIO_ERR_CONN_CLOSE;
    }

    /* successful receive */
    printf("my_IORecv: received %d bytes from %d\n", sz, sockfd);
    return recvd;
}

int my_IOSend(WOLFSSH *ssh, char *buff, int sz, void *ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to write to.
     * This can be changed by calling wolfSSL_SetIOWriteCtx(). */
    int sockfd = *(int *)ctx;
    int sent;
    (void)ssh;

    /* Receive message from socket */
    if ((sent = (int)send(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        fprintf(stderr, "IO SEND ERROR: ");
        switch (errno)
        {
        case EWOULDBLOCK:
            fprintf(stderr, "would block\n");
            return WS_CBIO_ERR_WANT_READ;
        case ECONNRESET:
            fprintf(stderr, "connection reset\n");
            return WS_CBIO_ERR_CONN_RST;
        case EINTR:
            fprintf(stderr, "socket interrupted\n");
            return WS_CBIO_ERR_ISR;
        case EPIPE:
            fprintf(stderr, "socket EPIPE\n");
            return WS_CBIO_ERR_CONN_CLOSE;
        default:
            fprintf(stderr, "general error\n");
            return WS_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0)
    {
        printf("Connection closed\n");
        return 0;
    }

    /* successful send */
    printf("my_IOSend: sent %d bytes to %d\n", sz, sockfd);
    return sent;
}