# commitfinder

This is a research project for finding commits with certain properties. It has a CLI interface -
run `./commitfinder` for help. It requires the pygit2, requests and cached_property libraries.

The script uses a directory named `workdir`, in the same directory as the script, for repository
checkouts and caching data from APIs between runs. When done using this script you may want to
delete that directory, as it can be quite large (~30G).
