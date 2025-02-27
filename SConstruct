#!/usr/bin/env python
import os

def normalize_path(val, env):
    return val if os.path.isabs(val) else os.path.join(env.Dir("#").abspath, val)

def validate_parent_dir(key, val, env):
    if not os.path.isdir(normalize_path(os.path.dirname(val), env)):
        raise UserError("'%s' is not a directory: %s" % (key, os.path.dirname(val)))

libname = "mariadb_connector"
projectdir = "demo"

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

env = SConscript("godot-cpp/SConstruct", {"env": env, "customs": customs})

if env["platform"] == "windows":
    env.Append(LIBS=["ws2_32", "bcrypt"])  # Link Windows networking and bcrypt
    env.Append(LINKFLAGS=["-static-libgcc", "-static-libstdc++"])  # Ensure static linking

env.Append(CPPPATH=[
    "src/",
    "src/ed25519_ref10",
    "src/mbedtls/include",
    "src/mbedtls/include/mbedtls",
    "src/mbedtls/include/psa"
])

sources = Glob("src/*.cpp") + Glob("src/ed25519_ref10/*.cpp") + Glob("src/mbedtls/library/*.c")

# Remove "lib" prefix from the shared library file
# env["SHLIBPREFIX"] = ""

# Strip "template_" from target name if present
clean_target = env["target"].replace("template_", "")

# Detect architecture suffix for ARM64 builds
arch_suffix = env.get("arch", "")

# Ensure filename includes lib_, platform, arch (if applicable), and cleaned target type
file = "lib_{}.{}.{}.{}{}".format(libname, env["platform"], clean_target, arch_suffix, env["SHLIBSUFFIX"])

if env["platform"] == "macos":
    platlibname = "lib_{}.{}.{}".format(libname, env["platform"], clean_target)
    file = "{}.framework/{}".format(platlibname, platlibname)

libraryfile = "{}/libs/{}".format(projectdir, file)  # Store all output in demo/lib/
library = env.SharedLibrary(
    libraryfile,
    source=sources,
)

default_args = [library]
if localEnv.get("compiledb", False):
    default_args += [compilation_db]
Default(*default_args)
