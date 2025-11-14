This directory contains handlers for Offchain methods. Entries may be symlinks
or may be placed here directly (such as for sys_register_caller.py).

Each handler must contain a get_handlers() which returns the method signatures
and functions to register. The top-level progam calls
"load_dotenv(find_dotenv())" before registering handlers.
