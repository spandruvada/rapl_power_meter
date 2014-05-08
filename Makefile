CC		= $(CROSS_COMPILE)gcc
BUILD_OUTPUT	:= $(PWD)
PREFIX		:= /usr
DESTDIR		:=

rapl_power_meter : rapl_power_meter.c index_html.h
CFLAGS +=	-Wall
CFLAGS +=	-DLOCKF_SUPPORT

%: %.c
	@mkdir -p $(BUILD_OUTPUT)
	$(CC) $(CFLAGS) $< -o $(BUILD_OUTPUT)/$@

.PHONY : clean
clean :
	@rm -f $(BUILD_OUTPUT)/rapl_power_meter

install : rapl_power_meter
	install -d  $(DESTDIR)$(PREFIX)/bin
	install $(BUILD_OUTPUT)/rapl_power_meter $(DESTDIR)$(PREFIX)/bin/rapl_power_meter
