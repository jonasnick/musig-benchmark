main: main.c
	gcc -Wextra -Wall -lsecp256k1 -o musig-benchmark main.c
debug:
	gcc -DDebug -Wextra -Wall -g -fsanitize=address -fsanitize=undefined -lsecp256k1 -o musig-benchmark main.c
