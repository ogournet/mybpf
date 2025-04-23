
BUILDDIR ?= build
V ?= 0
ifeq ($V,1)
  ninja_opts = --verbose
  Q =
else
  Q = @
endif

.PHONY: all
all: $(BUILDDIR)/build.ninja
	$Q ninja -C $(BUILDDIR) $(ninja_opts)

.PHONY: all
clean:
	$Q ninja -C $(BUILDDIR) clean $(ninja_opts)

.PHONY: install
install: $(BUILDDIR)/build.ninja
	$Q meson install -C $(BUILDDIR)

meson_opts = --warnlevel=2
meson_opts += $(MESON_EXTRA_OPTS)

$(BUILDDIR)/build.ninja:
	meson setup $(BUILDDIR) $(meson_opts)
