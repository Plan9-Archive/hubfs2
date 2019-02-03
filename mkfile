</$objtype/mkfile

TARG=hubfs\
	hubshell\

BIN=/$objtype/bin

UPDATE=\
	mkfile\
	hubfs.c\
	hubshell.c\

</sys/src/cmd/mkmany

$O.hubfs: hubfs.$O ratelimit.$O
	$LD -o $target $prereq

$O.hubshell: hubshell.$O
	$LD -o $target $prereq

install:V:
	for (i in $TARG)
		mk $MKFLAGS $i.install
