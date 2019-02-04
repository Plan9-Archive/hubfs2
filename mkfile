</$objtype/mkfile

BIN=/$objtype/bin
MAN=/sys/man/4
MANFILES=hubfs.man

TARG=\
	hubfs\
	hubshell\

HFILES=\
	ratelimit.h\

</sys/src/cmd/mkmany

$O.hubfs: hubfs.$O ratelimit.$O
	$LD $LDFLAGS -o $target $prereq

$O.hubshell: hubshell.$O
	$LD $LDFLAGS -o $target $prereq

/rc/bin/%:	%.rc
	cp $stem.rc $target

install.rc:V: /rc/bin/hub

install:V: install.rc
