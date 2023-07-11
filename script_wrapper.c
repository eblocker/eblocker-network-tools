/*
 * Copyright 2020 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*

  Wrapper for scripts that must run as root.

  Argument:
  * name of the script to execute.
  * argument for script (optional)

  Only scripts in directory /opt/eblocker-icap/scripts/ can be executed.

 */
int main(int argc,char **argv)
{
    const char* basepath = "/opt/eblocker-icap/scripts/";
    char path_input[PATH_MAX];
    char path_real[PATH_MAX];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <script> [<argument>]\n", argv[0]);
        return 1;
    }

    if (setuid(0) != 0) {
        perror("Could not setuid(0)");
        return 1;
    }

    if (setgid(0) != 0) {
        perror("Could not setgid(0)");
        return 1;
    }

    const char* command = argv[1];
    strcpy(path_input, basepath);
    strncat(path_input, argv[1], PATH_MAX - strlen(basepath) - 1);

    if (realpath(path_input, path_real) == NULL) {
        perror("Could not get realpath");
        return 1;
    }

    if (strncmp(path_input, path_real, PATH_MAX) != 0) {
        fprintf(stderr, "Invalid command location\n");
        return 1;
    }

    int retval = execvpe(path_real, argv + 1, NULL);
    perror("Could not execute command");
    return retval;
}
