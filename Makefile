main: main.c
	$(CC) -Wextra -Wall -lsecp256k1 -o musig-benchmark main.c
debug:
	$(CC) -DDebug -Wextra -Wall -g -fsanitize=address -fsanitize=undefined -lsecp256k1 -o musig-benchmark main.c
