#!/usr/bin/env python
import os

def normalize_path(val, env):
    return val if os.path.isabs(val) else os.path.join(env.Dir("#").abspath, val)

def validate_parent_dir(key, val, env):
    if not os.path.isdir(normalize_path(os.path.dirname(val), env)):
        raise UserError("'%s' is not a directory: %s" % (key, os.path.dirname(val)))

libname = "mariadb_connector"
outputdir = "demo/addons/godot-mariadb-connector/bin"

localEnv = Environment(tools=["default"], PLATFORM="")

customs = ["custom.py"]
customs = [os.path.abspath(path) for path in customs]

opts = Variables(customs, ARGUMENTS)
opts.Add(
    BoolVariable(
        key="compiledb",
        help="Generate compilation DB (`compile_commands.json`) for external tools",
        default=localEnv.get("compiledb", False),
    )
)
opts.Add(
    PathVariable(
        key="compiledb_file",
        help="Path to a custom `compile_commands.json` file",
        default=localEnv.get("compiledb_file", "compile_commands.json"),
        validator=validate_parent_dir,
    )
)
opts.Update(localEnv)

Help(opts.GenerateHelpText(localEnv))

env = localEnv.Clone()
env["compiledb"] = False

env.Tool("compilation_db")
compilation_db = env.CompilationDatabase(
    normalize_path(localEnv["compiledb_file"], localEnv)
)
env.Alias("compiledb", compilation_db)

env = SConscript("src/godot-cpp/SConstruct", {"env": env, "customs": customs})

if env["platform"] == "windows":
    env.Append(LIBS=["ws2_32", "bcrypt"])  # Link Windows networking and bcrypt
    env.Append(LINKFLAGS=["-static-libgcc", "-static-libstdc++"])  # Ensure static linking

env.Append(CPPPATH=[
    "src/",
    "src/ed25519_ref10",
    "src/mbedtls/include",
    "src/mbedtls/include/mbedtls",
    "src/mbedtls/include/psa",
    "src/argon2/",
    "src/argon2/blake2"
])

sources = Glob("src/*.cpp") + Glob("src/ed25519_ref10/*.cpp") + Glob("src/mbedtls/library/*.c")

argon2_sources = [
    "src/argon2/argon2.c",
    "src/argon2/core.c",
    "src/argon2/encoding.c",
    "src/argon2/thread.c",
    "src/argon2/blake2/blake2b.c"
]

# Detect architecture suffix for ARM64 builds
arch_suffix = env.get("arch", "")

if arch_suffix not in ["aarch64", "arm64"]:
    argon2_sources.append("src/argon2/opt.c")  # only include opt.c on x86
else:
    print("Skipping opt.c for ARM64 (no SSE)")


sources += [env.File(f) for f in argon2_sources]

if env["target"] in ["editor", "template_debug"]:
	try:
		doc_data = env.GodotCPPDocData("src/gen/doc_data.gen.cpp", source=Glob("doc_classes/*.xml"))
		sources.append(doc_data)
	except AttributeError:
		print("Not including class reference as we're targeting a pre-4.3 baseline.")

if env["arch"] == "arm64":
    env.Append(CCFLAGS=["-DARGON2_NO_OPT"])

# Remove "lib" prefix from the shared library file
# env["SHLIBPREFIX"] = ""

# Strip "template_" from target name if present
clean_target = env["target"].replace("template_", "")

# Ensure filename includes lib_, platform, arch (if applicable), and cleaned target type
file = "libgd_{}.{}.{}.{}{}".format(libname, env["platform"], clean_target, arch_suffix, env["SHLIBSUFFIX"])

if env["platform"] == "macos":
    platlibname = "lib_{}.{}.{}".format(libname, env["platform"], clean_target)
    file = "{}.framework/{}".format(platlibname, platlibname)

libraryfile = "{}/{}".format(outputdir, file)  # Store all output in demo/lib/
library = env.SharedLibrary(
    libraryfile,
    source=sources,
)

default_args = [library]
if localEnv.get("compiledb", False):
    default_args += [compilation_db]
Default(*default_args)
