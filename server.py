from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
import os
from pathlib import Path

# Mandatory rules
# - Used descriptive or precise docstring. The docstring is the interface.
# - The docstring should:
#       - Name the tool's purpose
#       - When to and not to use it
#       - Distinguish it from it's siblings
#       - Possibly warn the host from it's consequences(destructive nature)
#       - When a tool fails, tell the caller what to do instead
# Order matters.

# 1. Initialize the MCP server.
#
# The name helps the MCP host/AI understand the purpose of this server.
mcp = FastMCP("Context Editor")

# 2. Define the project root.
#
# The "project" directory is located beside this server.py file:
#
# mcp-file-server/
# ├── server.py
# └── project/
#
# .resolve() converts the path into a canonical absolute path.
# This also gives us a stable path to use for security checks below.
PROJECT_ROOT = (Path(__file__).resolve().parent / "project").resolve()

# 3. Define files and directories that the MCP server must not expose.
#
# These protections apply even when the AI explicitly requests the file
# through read_project_file().
#
# This is important because hiding a file from project://structure is not
# sufficient protection. The AI could otherwise guess the filename.
#
# The names below are deliberately conservative for this training project.

SENSITIVE_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",

    # Private key / credential files.
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",

    # Generic credential files.
    "credentials",
    "credentials.json",
}

SENSITIVE_FILE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}

SENSITIVE_DIRECTORY_NAMES = {
    ".git",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config",

    # Development environments can contain credentials/tokens.
    ".venv",
    "venv",
    "node_modules",
}

# **One caveat:** this is a training-grade protection policy, not a full secrets-scanning/security boundary. A file containing a secret but having an ordinary name such as config.json would still be readable. That's appropriate for where we are now; we can later discuss the difference between path-based access control and content-based secret detection.

def is_sensitive_path(path: Path) -> bool:
    """Return True if a path contains a protected file or directory."""

    # Check every component of the path.
    #
    # For example:
    #
    #     project/config/.env
    #
    # has the path parts:
    #
    #     ("project", "config", ".env")
    #
    # We only need to inspect the path relative to PROJECT_ROOT.
    try:
        relative_path = path.relative_to(PROJECT_ROOT)
    except ValueError:
        # This should normally be caught by the sandbox check before this
        # function is called, but failing closed is safer.
        return True

    parts = relative_path.parts

    # Check directory names.
    #
    # We exclude the final component from this check because it is handled
    # separately as the filename.
    for part in parts[:-1]:
        if part in SENSITIVE_DIRECTORY_NAMES:
            return True

    # Check the filename.
    filename = parts[-1]

    if filename.lower() in SENSITIVE_FILE_NAMES:
        return True

    # Check sensitive extensions.
    if Path(filename).suffix.lower() in SENSITIVE_FILE_SUFFIXES:
        return True

    return False

# 4. Expose a Tool.
#
# An MCP tool is an operation that the AI/MCP host can explicitly execute.
#
# FastMCP's @mcp.tool() decorator registers this function as an MCP tool.
# When the MCP host calls the tool, FastMCP passes the arguments to this
# function and returns its result through the MCP protocol.

@mcp.tool()
def read_project_file(file_path: str) -> str:
    """Read a non-sensitive text file from the project directory.

    Args:
        file_path: Relative path of the file inside the project directory.
                   Example: "src/index.html"
    """

    try:
        # Resolve the requested path before checking access.
        #
        # This converts paths containing .. and . and symlinks 
        # into their actual canonical location before the 
        # sandbox check is performed.
        
        # the sandbox check.
        full_path = (PROJECT_ROOT / file_path).resolve()

        # Security check #1:
        #
        # Verify that the resolved path is actually inside PROJECT_ROOT.
        #
        # This prevents path traversal such as:
        #
        #     ../../../some/secret/file
        #
        # from escaping the project directory.
        if not full_path.is_relative_to(PROJECT_ROOT):
            # return "Error: Access denied. File is outside the project directory."
            raise ToolError("Access denied. File is outside the project directory.")

        # Security check #2:
        #
        # Prevent access to known sensitive files and directories.
        #
        # This check happens AFTER resolve(), which is important because
        # symlinks and ".." components have already been resolved.
        if is_sensitive_path(full_path):
            # return "Error: Access denied. This file or directory is protected."
            raise ToolError("Access denied. This file or directory is protected.")

        # Only files can be read by this tool.
        if not full_path.is_file():
            # return f"Error: File '{file_path}' not found."
            raise ToolError(f"File '{file_path}' not found.")

        # Read the file as UTF-8 text.
        return full_path.read_text(encoding="utf-8")

    except UnicodeDecodeError:
        # return f"Error: File '{file_path}' is not a valid UTF-8 text file."
        raise ToolError(f"File '{file_path}' is not a valid UTF-8 text file.")

    except PermissionError:
        # return f"Error: Permission denied when reading '{file_path}'."
        raise ToolError(f"Permission denied when reading '{file_path}'.")

    except OSError as e:
        # return f"Error reading file '{file_path}': {e}"
        raise ToolError(f"Error reading file '{file_path}': {e}")

# 5. Expose a Resource.
#
# An MCP resource provides data that the MCP host can request.
#
# "project://" is a URI scheme chosen by this application.
#
# The resource provides a recursive list of files in the project directory.

@mcp.resource("project://structure")
def get_project_structure() -> str:
    """Return a list of non-sensitive files in the project directory."""

    # file_list = []
    file_list: list[str] = []

    # os.walk() recursively traverses the project directory.
    #
    # At each directory it yields:
    #
    #     root, dirs, files
    #
    # Modifying dirs[:] in place tells os.walk() which directories it should
    # descend into.
    for root, dirs, files in os.walk(PROJECT_ROOT):

        # Do not descend into hidden/sensitive directories.
        dirs[:] = [
            directory
            for directory in dirs
            if not directory.startswith(".")
            and directory not in SENSITIVE_DIRECTORY_NAMES
        ]

        for file in files:

            # Ignore hidden files.
            if file.startswith("."):
                continue

            file_path = Path(root) / file

            # Apply the same sensitive-file policy used by the read tool.
            if is_sensitive_path(file_path):
                continue

            # Convert the absolute path into a path relative to PROJECT_ROOT.
            relative_path = file_path.relative_to(PROJECT_ROOT)

            file_list.append(relative_path.as_posix())

    return "\n".join(sorted(file_list))

@mcp.tool()
def write_project_file(file_path: str, content: str) -> str:
    """Create a new text file in the project directory.

    Fails if the file already exists. Use overwrite_project_file
    (if available) to replace an existing file.

    Args:
        file_path: Relative path for the new file, e.g. "src/notes.md".
        content: The UTF-8 text content to write.
    """
    try:
        full_path = (PROJECT_ROOT / file_path).resolve()

        # Same two security checks as the read tool, in the same order.
        if not full_path.is_relative_to(PROJECT_ROOT):
            # return "Error: Access denied. Path is outside the project directory."
            raise ToolError("Access denied. Path is outside the project directory.")
        if is_sensitive_path(full_path):
            # return "Error: Access denied. This path is protected."
            raise ToolError("Access denied. This path is protected.")

        # Refuse to overwrite.
        if full_path.exists():
            # return f"Error: File '{file_path}' already exists."
            raise ToolError(f"File '{file_path}' already exists.")

        # Create parent directories if needed. Decide whether you want this.
        full_path.parent.mkdir(parents=True, exist_ok=True)

        full_path.write_text(content, encoding="utf-8")

        return f"Created '{file_path}' ({len(content)} characters)."

    except PermissionError:
        # return f"Error: Permission denied when writing '{file_path}'."
        raise ToolError(f"Permission denied when writing '{file_path}'.")
    except OSError as e:
        # return f"Error writing file '{file_path}': {e}"
        raise ToolError(f"Error writing file '{file_path}': {e}")

@mcp.tool()
def overwrite_project_file(file_path: str, content: str) -> str:
    """Replace the contents of an existing text file in the project directory.

    Use this only when the file already exists. To create a new file, use
    write_project_file instead. This operation is destructive: the previous
    contents are lost.

    Args:
        file_path: Relative path of an existing file, e.g. "src/notes.md".
        content: The new UTF-8 text content to write.
    """
    try:
        full_path = (PROJECT_ROOT / file_path).resolve()

        if not full_path.is_relative_to(PROJECT_ROOT):
            raise ToolError("Access denied: path is outside the project directory.")

        if is_sensitive_path(full_path):
            raise ToolError("Access denied: this path is protected.")

        if not full_path.exists():
            raise ToolError(
                f"File '{file_path}' does not exist. "
                f"Use write_project_file to create it."
            )

        if not full_path.is_file():
            raise ToolError(f"'{file_path}' is not a regular file.")

        old_size = full_path.stat().st_size
        full_path.write_text(content, encoding="utf-8")
        new_size = len(content)

        return (
            f"Overwrote '{file_path}' "
            f"({old_size} -> {new_size} characters)."
        )

    except PermissionError:
        raise ToolError(f"Permission denied when writing '{file_path}'.")
    except OSError as e:
        raise ToolError(f"Error writing file '{file_path}': {e}")

# 6. Start the MCP server.
#
# When server.py is executed directly, run the MCP server over stdio
# (standard input/output).
#
# stdio is commonly used for locally running MCP servers because the
# MCP host launches the server process and communicates with it directly.

# mcp.run(transport="stdio")
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
