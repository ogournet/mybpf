
fs = import('fs')

bpf_sources = files('pass.c', 'map_resize.c', 'cpumap.c', 'signal.c', 'bpf_var.c', 'pkt_queue.c', 'ipfrag.c')


# ebpf program needs vmlinux.h header file. it may be generated with bpftool.
vmlinux = custom_target('vmlinux',
			command: ['bpftool', 'btf', 'dump', 'file',
				  '/sys/kernel/btf/vmlinux', 'format', 'c' ],
			output: 'vmlinux.h',
			capture: true,
)

# Build BPF codes
foreach bsrc : bpf_sources
  name = fs.replace_suffix(fs.name(bsrc), '')
  bpf_obj = custom_target('bpf-' + name,
			  input : bsrc,
			  output : name + '.ll',
			  command : [clang, '-g', '-O2', '-c', '-emit-llvm',
				     '-target', 'bpf',
				     '-D__TARGET_ARCH_' + arch,
				     '-I' + meson.current_source_dir(),
				     '-I' + libbpf_inc,
				     clang_includes,
				     '-o', '@OUTPUT@', '@INPUT@'],
			  depends : vmlinux
  )

  bpf_prog = custom_target('bpf-' + name + '-bin',
			   input : bpf_obj,
			   output : name + '.bpf',
			   command : [llc, '-march=bpf', '-filetype=obj',
				      '-o', '@OUTPUT@', '@INPUT@'],
			   install_dir: get_option('libdir') / 'bpf',
			   install: true
  )
endforeach

#
## Generate BPF skeleton
## we don't currently use it
# bpf_skel = custom_target('bpf-skel',
# 			 input : bpf_prog,
# 			 depends: bpf_prog,
# 			 output : 'bpf-skel.h',
# 			 command : [bpftool, 'gen', 'skeleton', '@INPUT@'],
# 			 capture : true
# )
