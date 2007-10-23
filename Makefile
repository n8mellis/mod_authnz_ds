APXS = /opt/local/apache2/bin/apxs
LIB_resolv = -lresolv

CPPFLAGS = -I.
LDFLAGS = $(LIB_resolv) -framework Security
CFLAGS = 

# APXS_CPPFLAGS = ${shell [ -n "${CPPFLAGS}" ] && echo ${CPPFLAGS} | sed -e 's/\([^ ]*\)/-Wc,\1/g'}
# APXS_LDFLAGS	= ${shell [ -n "${LDFLAGS}"	 ] && echo ${LDFLAGS}	 | sed -e 's/\([^ ]*\)/-Wl,\1/g'}

APXS_CPPFLAGS = -Wc,-I.
APXS_LDFLAGS = -Wl,"-framework DirectoryService" -Wl,-lresolv

# echo $(APXS_CPPFLAGS)

all: src/mod_authnz_ds.so

src/mod_authnz_ds.so: src/mod_authnz_ds.c
	$(APXS) -c $(APXS_CPPFLAGS) $(APXS_CFLAGS) $(APXS_LDFLAGS) src/mod_authnz_ds.c

install:
	$(APXS) -c -i -a $(APXS_CPPFLAGS) $(APXS_CFLAGS) $(APXS_LDFLAGS) src/mod_authnz_ds.c

clean:
	for i in . src; do \
		$(RM) $$i/*.{o,so,a,la,lo,slo} core; \
		$(RM) -rf $$i/.libs; \
	done

distclean: clean
	$(RM) config.h config.status Makefile config.log
	$(RM) -rf autom4te.cache
	
make_release:
	echo "Did you increase version numbers?"
	autoconf
	$(RM) -rf autom4te.cache
	$(RM) -rf .cvsignore
	$(RM) -rf CVS

.PHONY: all install clean distclean
