# clibcni

CNI (Container Network Interface), a Cloud Native Computing Foundation project.
clibcni is a library used by iSulad to configure network interfaces in containers, following
the specification of CNI (Container Network Interface), a Cloud Native Computing Foundation project.

## How to Contribute

We always welcome new contributors. And we are happy to provide guidance for the new contributors.
iSulad follows the kernel coding conventions. You can find a detailed introduction at:

- https://www.kernel.org/doc/html/v4.10/process/coding-style.html

## Building

Without considering distribution specific details a simple

    mkdir -p build && cd ./build && cmake .. && make && sudo make install

is usually sufficient.

## Licensing

clibcni is licensed under the Mulan PSL v1.
