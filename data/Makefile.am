CLEANFILES = \
	wolpertinger.db

wolper_data_DATA = \
        create_db.py \
        wolper-services \
	wolpertinger.db

wolper_datadir = \
	$(pkgdatadir)

install-data-hook:
	mkdir -p $(DESTDIR)/$(localstatedir)/@PACKAGE@

wolpertinger.db:
	./create_db.py
