# Backend testing

The recommended local environment lives outside this Git repository at:

`/Users/may/Coding/HEIDI/.environments/backend-py311`

It uses Python 3.11 to match the backend Docker image. Create or refresh it
from the HEIDI workspace root with:

```bash
/opt/homebrew/bin/python3.11 -m venv .environments/backend-py311
.environments/backend-py311/bin/python -m pip install -r nginx-reverse-proxy/backend/requirements-dev.txt
```

Run the backend tests from this repository with:

```bash
../../.environments/backend-py311/bin/python -m pytest
```

The tests replace database clients with local fakes. They must not connect to
HEIDI, MXDB, FFCS or MongoDB Atlas. `heidi-test` shares production data and is
not an automated-test target.
