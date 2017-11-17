LDLIBS = -luci

PROGRAMS=meshconfig

all: $(PROGRAMS)

meshconfig: meshconfig.o crc.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) 

clean:
	rm -f *.o $(PROGRAMS)  


