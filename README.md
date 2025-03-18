<h1 align="center" style="font-size: 2.5em;">Godot MariaDB Connector Plugin</h1>

<p align="center">
  <img src="demo/addons/godot-mariadb-connector/godot-mariadb-connector.png" alt="MariaDB Connector" />
</p>

A **GDExtension-based** MariaDB connector for **Godot 4**, allowing direct database access from Godot without relying on third-party middleware.

## Features
- Connect to **MariaDB** databases directly from Godot.
- Perform queries, insert/update/delete operations, and handle results.
- Secure authentication with **SHA-1 and Ed25519 password hashing**.
- Cross-platform support (Linux, Windows, ARM64).
- Uses **GDExtension**, requiring no custom engine builds.

## Installation
### 1. Download the Addon
Clone or download the repository:
```sh
git clone https://github.com/sigrudds1/Godot-MariaDB-Connector-Plugin.git
```
Or download the latest release from **[Releases](https://github.com/sigrudds1/Godot-MariaDB-Connector-Plugin/releases)** or the **Godot Asset Library** *(when available)*.

### 2. Add to Your Godot Project
Move the **`addons/mariadb_connector/`** folder into your project's `addons/` directory.

### 3. GDExtension Auto-Detection
Since this is a **GDExtension**, it does **not** require enabling in the Godot plugin settings. Once the files are in place, Godot will automatically detect and load the extension.

*(Note: Behavior may be different when downloading from the Asset Library inside the editor.)*

## Usage
For detailed usage examples, please refer to the **Demo Project** included in the repository.

You can find the demo inside the `demo/` folder, which demonstrates how to:

- Connect to a MariaDB database.
- Execute queries (SELECT, INSERT, UPDATE, DELETE).
- Handle results properly.

## Build Instructions (For Contributors)

### Dependencies

Ensure you have:

- **Godot 4.3+**
- **SCons** (for building)
- **GCC or Clang** (Linux/macOS) / **MinGW** (Windows)
- **MariaDB C Connector**

### Building

```sh
scons platform=linux arch=x86_64
scons platform=windows arch=x86_64
scons platform=linux arch=arm64
```

## License

This project is licensed under the **MIT License**.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Submit a Pull Request.

## Support

For issues, open a ticket on [GitHub Issues](https://github.com/sigrudds1/Godot-MariaDB-Connector-Plugin/issues).

