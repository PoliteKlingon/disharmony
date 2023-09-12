LDLIBS += -lpthread
CFLAGS += -lpthread
# CFLAGS += -std=c99 -Wall -Wextra --pedantic

all: disharmony

disharmony: disharmony.o disharmony_server.o disharmony_client.o disharmony_protocol.o encoding.o

disharmony.o: disharmony_server.h disharmony_client.h disharmony_protocol.h encoding.h

disharmony_server.o: disharmony_server.h disharmony_protocol.h

disharmony_client.o: disharmony_client.h disharmony_protocol.h encoding.h

disharmony_protocol.o: disharmony_protocol.h

encoding.o: encoding.h

clean: 
	$(RM) *.o

distclean: clean
	$(RM) disharmony

.PHONY: all clean distclean
