project('mybpf', 'c',
	version : '0.1',
	meson_version: '>= 0.59.0',
	default_options : ['warning_level=2', 'c_std=gnu99']
)

cc = meson.get_compiler('c')
clang = find_program('clang', required : true)
llc = find_program('llc', required : true)
llvm_strip = find_program('llvm-strip', required : true)

# Compile flags
add_project_arguments('-g', language : 'c')

# Get architecture
arch = run_command('uname', '-m', check: true).stdout().strip()
arch = arch.replace('x86_64', 'x86').replace('aarch64', 'arm64').replace('ppc64le', 'powerpc').replace('mips', 'mips').replace('arm', 'arm').replace('riscv64', 'riscv')

# Dependencies
bpftool = find_program('bpftool', required: true)
libbpf_dep = dependency('libbpf')
libxdp_dep = dependency('libxdp')
libev_dep = declare_dependency(link_args: '-lev')
libbpf_inc = libbpf_dep.get_variable('includedir')

# Get Clang's default includes
clang_includes = []
search_start = false
foreach line : run_command(clang, '-v', '-E', '-', check: false, capture: true).stderr().split('\n')
	if search_start
		if line.strip() == 'End of search list.'
			break
		endif
		if line.strip().startswith('/')
			clang_includes += ['-idirafter', line.strip()]
		endif
	elif line.strip() == '#include <...> search starts here:'
		search_start = true
	endif
endforeach

src = []

subdir('src/bpf')
subdir('src')

executable('mybpf', src,
	   dependencies: [libbpf_dep, libxdp_dep, libev_dep],
	   install: true
)
