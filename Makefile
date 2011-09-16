include Makefile.in

PROGRAM = xportscan

OBJECTS = $(PROGRAM).o

CPPFLAGS = $(WX_CPP_FLAGS)

LIBS = $(WX_L_FLAGS)


all:       $(PROGRAM)

$(PROGRAM):. $(OBJECTS)
	c++ $(CPPFLAGS) -o $@ $(OBJECTS) $(LIBS)
	mv $(PROGRAM) ..

install:
	install -c ../$(PROGRAM) /usr/bin
	install -c ../portlist.txt /
	echo "program + portlist.txt were installed in /usr/bin/"
	echo "run make uninstall to remove files"

clean:
	rm -f *.o *.d core

uninstall:
	rm -f /usr/bin/$(PROGRAM)
	rm -f /portlist.txt
