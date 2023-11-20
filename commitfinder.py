#!/usr/bin/python

# Copyright Red Hat
#
# This file is part of commitfinder.
#
# commitfinder is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Adam Williamson <awilliam@redhat.com>

"""
Script for finding and producing information about repository commits
with specific properties.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import re

from cached_property import cached_property
import pygit2
import requests

from pygit2 import Commit, Walker

# pylint:disable=invalid-name
logger = logging.getLogger(__name__)

WORKDIR = f"{os.path.dirname(os.path.realpath(__file__))}/workdir"


def print_progress_bar(iteration, total, prefix="", suffix="", length=50, fill="█"):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + "-" * (length - filled_length)
    print("\r%s |%s| %s%% %s" % (prefix, bar, percent, suffix), end="\r")
    if iteration == total:
        print()


CVE_REGEX = re.compile(r"(CVE-\d{4}-\d+)")


def get_cve_id(s: str) -> str | None:
    """Return the first CVE ID found in the string."""
    match = CVE_REGEX.search(s)
    if match:
        return match.group(0)
    return None


def is_go_file(fname: str) -> bool:
    return fname.endswith(".go")


def is_go_code_file(fname: str) -> bool:
    return is_go_file(fname) and not fname.lower().endswith("_test.go")


def is_java_file(fname: str) -> bool:
    return fname.endswith(".java")


def is_java_code_file(fname: str) -> bool:
    return is_java_file(fname) and not fname.lower().endswith("Test.java")


def is_javascript_file(fname: str) -> bool:
    extensions = [".js", ".jsx", ".ts", ".tsx", ".json"]
    return any(fname.endswith(ext) for ext in extensions)


def is_javascript_code_file(fname: str) -> bool:
    return is_javascript_file(fname) and not any(
        fname.endswith(ext)
        for ext in [".test", ".spec", ".config", "eslintrc", "prettierrc", "babelrc"]
    )


def is_python_file(fname: str) -> bool:
    return fname.endswith(".py")


def is_python_code_file(fname: str) -> bool:
    return is_python_file(fname) and not (
        fname.startswith("test")
        or fname.startswith("doc/")
        or fname == "setup.py"
        or "/test_" in fname
    )


def select_javascript_files(files: list[str]) -> list[str]:
    return [f for f in files if is_javascript_file(f)]


def select_javascript_code_files(files: list[str]) -> list[str]:
    return [f for f in files if is_javascript_code_file(f)]


def select_python_code_files(files: list[str]) -> list[str]:
    return [fname for fname in files if is_python_code_file(fname)]


def select_python_files(files: list[str]) -> list[str]:
    return [fname for fname in files if is_python_file(fname)]


def select_go_code_files(files: list[str]) -> list[str]:
    return [fname for fname in files if is_go_code_file(fname)]


def select_go_files(files: list[str]) -> list[str]:
    return [f for f in files if is_go_file(f)]


def select_java_files(files: list[str]) -> list[str]:
    return [f for f in files if is_java_file(f)]


def select_java_code_files(files: list[str]) -> list[str]:
    return [f for f in files if is_java_code_file(f)]


"""
Identifies whether the given file is a code file
for the given language. Excludes secondary files
such as tests, configs, etc.
"""
CODE_FILE_IDENTIFIERS = {
    "python": is_python_code_file,
    "golang": is_go_code_file,
    "javascript": is_javascript_code_file,
    "java": is_java_code_file,
}

"""
Identifies whether or not a given file
is a code file for the given language.
"""
FILE_IDENTIFIERS = {
    "python": is_python_file,
    "golang": is_go_file,
    "javascript": is_javascript_file,
    "java": is_java_file,
}

"""
Selects only the files responsible for functionality
in each respective language. Excludes secondary
files such as tests, configs, etc.
"""
CODE_FILE_SELECTORS = {
    "python": select_python_code_files,
    "golang": select_go_code_files,
    "javascript": select_javascript_code_files,
    "java": select_java_code_files,
}

"""
Selects all files that are code files for the given language.
"""
FILE_SELECTORS = {
    "python": select_python_files,
    "golang": select_go_files,
    "javascript": select_javascript_files,
    "java": select_java_files,
}


class Repo:
    def __init__(self, url, source):
        self.url = url
        self.source = source
        # "https://github.com/psf/requests.git" -> "requests"
        self.name = url.split("/")[-1]
        if self.name.endswith(".git"):
            self.name = self.name[:-4]
        self.clonedir = f"{WORKDIR}/{source}"
        self.workdir = f"{self.clonedir}/{self.name}"
        if not os.path.exists(self.clonedir):
            os.makedirs(self.clonedir)
        if not os.path.exists(self.workdir):
            ret = subprocess.run(
                ["git", "clone", self.url], cwd=self.clonedir, capture_output=True
            ).returncode
            if ret:
                logger.warning("Clone of %s repo %s failed!", self.source, self.name)
        # init gitpython repo
        self.pyrepo = pygit2.Repository(self.workdir)

    @cached_property
    def headcommits(self):
        """
        A (summary, hex) representation of commits from the head
        branch in the repository.
        """
        headlast = self.pyrepo[self.pyrepo.head.target].id
        # this is a bit icky but it lets us use a comprehension while
        # guarding against completely empty commit messages
        return {
            commit.hex: (commit.message.splitlines() or ["XXXNOCOMMITMSGFOUNDXXX"])[0]
            for commit in self.pyrepo.walk(headlast, pygit2.GIT_SORT_TIME)
        }

    def find_stable_branches(self):
        return []

    def checkout_spec(self, spec):
        try:
            self.pyrepo.checkout(spec)
            return True
        except pygit2.InvalidSpecError:
            # https://github.com/libgit2/pygit2/issues/1217
            ret = subprocess.run(
                ["git", "checkout", spec], cwd=self.workdir, capture_output=True
            )
            return ret.returncode == 0

    def checkout_branch(self, branch):
        branch = self.pyrepo.branches[f"origin/{branch}"]
        return self.checkout_spec(branch)

    def is_cve_commit(self, commit: Commit, checkdiff: bool = True):
        msg = commit.message
        if "Merge: " in msg:
            # merge commit
            return False
        if "cve-1" in msg.lower() or "cve-2" in msg.lower():
            return True
        if checkdiff:
            try:
                diff = self.pyrepo.diff(
                    commit.parents[0], commit, context_lines=0
                ).patch.lower()
            except IndexError:
                # probably the first commit
                return False
            except pygit2.GitError as err:
                # hmmm
                logger.warning(
                    "WARNING: unexpected pygit error in is_cve_commit for %s: %s %s! %s",
                    self.source,
                    self.name,
                    commit.hex,
                    str(err),
                )
                return False
            except UnboundLocalError as err:
                # srsly wat
                logger.warning(
                    "WARNING: unexpected UnboundLocalError in is_cve_commit for %s: %s %s! %s",
                    self.source,
                    self.name,
                    commit.hex,
                    str(err),
                )
                return False
            for line in diff.splitlines():
                if not line.startswith("-") and ("cve-1" in line or "cve-2" in line):
                    return True
        return False

    def backport_of(self, commit: Commit):
        """
        Given a commit (object), guess if it's a backport of a commit
        from the head branch and - if possible - of which commit.
        A return of False means it's not a backport. A return of a
        string means it's a backport of that commit ID. A return of
        None means it's a backport but we don't know what commit it's
        a backport of.
        """
        msg = commit.message
        summ = (msg.splitlines() or [""])[0]
        msg = msg.lower()
        if not ("backport" in msg or "cherry picked from" in msg):
            return False
        # this check looks odd, but there are repos with commits on
        # HEAD which looks like backports and those same commits in
        # other branches, e.g. github aio-libs/aiohttp 74e3d74 . So
        # we'll ignore any commit that is in headcommits
        if commit.hex in self.headcommits:
            return False
        for hcomm in self.headcommits:
            # very safe check
            if (
                f"backport of {hcomm[:7]}" in msg
                or f"cherry picked from commit {hcomm[:7]}" in msg
            ):
                return hcomm
            # bit more dangerous...
            if hcomm[:7] in msg:
                return hcomm
            # summary match check...
            hsumm = self.headcommits[hcomm]
            if len(hsumm) > 15 and hsumm in summ:
                return hcomm
        if "backport of" in msg or "cherry picked from" in msg:
            return None
        return False

    def all_commits(self, branch: str) -> Walker | None:
        if not branch.startswith("origin/"):
            branch = f"origin/{branch}"
        try:
            pybranch = self.pyrepo.branches[branch]
            last = self.pyrepo[pybranch.target]
            return self.pyrepo.walk(last.id, pygit2.GIT_SORT_TIME)
        except pygit2.GitError as err:
            logger.warning(
                "WARNING: unexpected pygit error in all_commits for %s: %s! %s",
                self.source,
                self.name,
                str(err),
            )
            return None

    def files_created(self, commit: Commit) -> list:
        """Returns a tuple of filenames created by a given commit."""
        if isinstance(commit, str):
            commit = self.pyrepo.revparse_single(commit)
        patch = self.pyrepo.diff(commit.parents[0], commit).patch
        patchfiles = []
        waitforfile = False
        for line in patch.splitlines():
            if waitforfile:
                if line.startswith("+++"):
                    # this assumes the line always looks like:
                    # +++ b/(filepath)
                    patchfiles.append(line[6:])
                    waitforfile = False
            elif "new file mode" in line:
                waitforfile = True
        return patchfiles

    def files_touched(self, commit: Commit) -> list:
        return [
            line.split()[-1]
            for line in self.pyrepo.diff(commit.parents[0], commit)
            .stats.format(pygit2.GIT_DIFF_STATS_NUMBER, 10)
            .splitlines()
        ]

    def files_renamed(self, commit: Commit) -> list[dict]:
        """
        Given a commit, returns a list containing all of the files that were renamed,
        including their old names and new name.
        """
        renamed = []
        diff = self.pyrepo.diff(commit.parents[0], commit)
        diff.find_similar()
        for delta in diff.deltas:
            if delta.status == pygit2.GIT_DELTA_RENAMED:
                renamed.append(
                    {"old_file": delta.old_file.path, "new_file": delta.new_file.path}
                )
        return renamed

    def patch_from_commit(self, commit: Commit, filenames: list[str]) -> str:
        """
        Return the patch text for a given commit. If filenames is
        [], give the whole patch text; otherwise give the patch text
        only for the specified filename(s). Uses subprocess because
        pygit2 does not yet wrap the filename limiting stuff.
        """
        args = ["git", "diff", f"{commit.hex}^", commit.hex]
        if filenames:
            args.append("--")
            args.extend(filenames)
        return subprocess.check_output(
            args,
            cwd=self.workdir,
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
        )

    def file_from_commit(self, commit: Commit, filename: str):
        """
        Show a file from a commit. Thanks to
        https://github.com/libgit2/pygit2/issues/752 ...
        """
        return self.pyrepo.revparse_single(f"{commit.hex}:{filename}").data.decode(
            "utf-8"
        )

    def code_files_touched(
        self, commit: Commit, selected_languages: list[str]
    ) -> list[str]:
        files_touched = self.files_touched(commit)
        code_files = []
        for lang in selected_languages:
            code_files.extend(CODE_FILE_SELECTORS[lang](files_touched))
        return code_files

    def code_files_renamed(
        self, commit: Commit, selected_languages: list[str]
    ) -> list[dict]:
        """
        Given a commit and a set of selected languages, this returns a list of all the files
        that were renamed, and their filepaths.
        """
        selected_renames = []
        renamed_files = self.files_renamed(commit)
        for pair in renamed_files:
            either_is_code_file = False
            for lang in selected_languages:
                if CODE_FILE_IDENTIFIERS[lang](
                    pair["old_file"]
                ) or CODE_FILE_IDENTIFIERS[lang](pair["new_file"]):
                    either_is_code_file = True
                    break
            if either_is_code_file:
                selected_renames.append(pair)
        return selected_renames

    def find_backport_commits(self, selected_languages: list[str]) -> list:
        """Find backport commits."""
        backports = []
        checked = set()
        for branch in self.pyrepo.branches.remote:
            try:
                if self.pyrepo.branches[branch].is_head():
                    # we're looking for backports...
                    continue
                all_commits = self.all_commits(branch)
                if not all_commits:
                    continue
                for commit in all_commits:
                    if commit.hex in checked:
                        continue
                    checked.add(commit.hex)
                    if bportof := self.backport_of(commit):
                        touched = self.code_files_touched(commit, selected_languages)
                        renamed = self.code_files_renamed(commit, selected_languages)
                        backports.append((commit, bportof, touched, renamed))
            except ValueError:
                # this probably means the branch is HEAD or something
                pass
        return backports


class PackageRepo(Repo):
    def patch_modifies_one_file(self, rev, filename):
        """
        Given a commit rev and a filename, check out that commit,
        and - making an assumption that the file is a patch - check
        whether it modifies exactly one file.
        """
        if not self.checkout_spec(rev):
            logger.warning(
                "WARNING: could not checkout %s: %s %s!", self.source, self.name, rev
            )
            return False
        try:
            with open(f"{self.workdir}/{filename}", "r", encoding="utf-8") as patchfh:
                patch = patchfh.read()
        except FileNotFoundError:
            logger.warning(
                "WARNING: could not find patch file %s in %s: %s %s! Package ignored",
                filename,
                self.source,
                self.name,
                rev,
            )
            return False
        return patch.count("1 file changed") == 1

    def find_upstream_repo(self):
        """
        Try and find the upstream repo and return it as an instance if
        it's of a type we support.
        """
        try:
            if not self.checkout_branch(self.branches[0]):
                logger.warning(
                    "WARNING: could not checkout %s: %s %s!",
                    self.source,
                    self.name,
                    self.branches[0],
                )
        except KeyError:
            logger.warning(
                "WARNING: could not find branch %s in %s: %s!",
                self.branches[0],
                self.source,
                self.name,
            )
        if os.path.isfile(f"{self.workdir}/dead.package"):
            logger.debug(
                "%s: %s %s branch is retired, ignored",
                self.source,
                self.name,
                self.branches[0],
            )
            return None
        parsedspec = subprocess.run(
            ["rpmspec", "--parse", f"{self.workdir}/{self.name}.spec"],
            cwd=self.workdir,
            encoding="utf-8",
            capture_output=True,
        )
        if parsedspec.returncode:
            logger.warning(
                "WARNING: could not parse spec file %s.spec in %s: %s! Package ignored",
                self.name,
                self.source,
                self.name,
            )
            return None
        speclines = parsedspec.stdout.splitlines()
        for sline in speclines:
            if any(
                sline.lower().startswith(text)
                for text in ("url:", "source:", "source0:")
            ):
                ind = sline.find("github.com")
                if ind > -1:
                    sline = sline[ind:]
                    elems = sline.split("/")
                    try:
                        (group, proj) = (elems[1], elems[2])
                    except IndexError:
                        logger.warning("WARNING: could not parse source %s", sline)
                        return None
                    proj = proj.rstrip("/")
                    if proj.endswith(".git"):
                        proj = proj[:-4]
                    url = f"https://github.com/{group}/{proj}.git"
                    try:
                        return UpstreamRepo(url, "github")
                    except pygit2.GitError:
                        logger.warning(
                            "WARNING: could not clone or initialize upstream repo %s for %s: %s",
                            url,
                            self.source,
                            self.name,
                        )
        return None

    @property
    def branches(self):
        if self.source == "fedora":
            return ("rawhide", "f36", "f37", "f38", "el6", "epel7", "epel8")
        elif self.source == "cosstream":
            return ("c9s", "c8s")
        elif self.source == "centos":
            return ("c7", "c6", "c5", "c4")


class UpstreamRepo(Repo):
    pass


class RepoSource:
    def __init__(self, name):
        self.name = name

    def find_branches(self):
        raise NotImplementedError

    def get_repos(self):
        raise NotImplementedError


class PackageRepoSource(RepoSource):
    def find_branches(self):
        return []

    def repos_from_response(self, resp):
        raise NotImplementedError

    def next_from_response(self, resp):
        raise NotImplementedError

    def get_package_repos(self):
        reposfn = f"{WORKDIR}/{self.name}_repos.json"
        if os.path.exists(reposfn):
            with open(reposfn, "r", encoding="utf-8") as reposfh:
                repos = json.load(reposfh)
        else:
            repos = []
            next = self.apiurl
            while next:
                resp = requests.get(next)
                repos.extend(self.repos_from_response(resp))
                next = self.next_from_response(resp)
            with open(reposfn, "w", encoding="utf-8") as reposfh:
                json.dump(repos, reposfh)
        for repo in repos:
            try:
                yield PackageRepo(repo, self.name)
            except pygit2.GitError:
                logger.warning("Could not initialize %s repo %s!", self.name, repo)
                continue

    def get_upstream_repos(self):
        got = set()
        for repo in self.get_package_repos():
            urepo = repo.find_upstream_repo()
            if urepo:
                if not urepo.url in got:
                    got.add(urepo.url)
                    yield urepo


class PagureRepoSource(PackageRepoSource):
    def __init__(self, name, baseurl, namespace):
        super().__init__(name)
        self.baseurl = baseurl
        self.namespace = namespace
        self.apiurl = f"{baseurl}/api/0/projects?pattern=python-*&owner=!orphan&short=true&fork=false&per_page=100&namespace={namespace}"

    def repos_from_response(self, resp):
        return [
            f"{self.baseurl}/{self.namespace}/{project['name']}.git"
            for project in resp.json()["projects"]
        ]

    def next_from_response(self, resp):
        return resp.json()["pagination"]["next"]


class GitlabRepoSource(PackageRepoSource):
    def __init__(self, name, baseurl, group):
        super().__init__(name)
        self.baseurl = baseurl
        self.group = group
        self.apiurl = f"{baseurl}/api/v4/groups/{group}/projects?search=python-&archived=no&order_by=name&sort=asc&per_page=100"

    def repos_from_response(self, resp):
        return [project["http_url_to_repo"] for project in resp.json()]

    def next_from_response(self, resp):
        try:
            return resp.links["next"]["url"]
        except KeyError:
            # this means we hit the last page
            return None


# returns a list of all the affected files in the given commit
def get_affected_files(
    repo: UpstreamRepo,
    filepaths: list[str],
    upstream_commit_hash_before,
    upstream_commit_hash_after,
    backport_commit_hash_before,
    backport_commit_hash_after,
    # include_partials=False,
) -> list[dict]:
    files = []
    for fpath in filepaths:
        # decode_error = False
        # key_error = False
        keys = [
            ("upstream_before", upstream_commit_hash_before),
            ("upstream_after", upstream_commit_hash_after),
            ("backport_before", backport_commit_hash_before),
            ("backport_after", backport_commit_hash_after),
        ]
        file = {
            "filepath": fpath,
            "upstream_before": "",
            "upstream_after": "",
            "backport_before": "",
            "backport_after": "",
        }
        for key, commit_hash in keys:
            try:
                file[key] = repo.file_from_commit(commit_hash, fpath)
            except KeyError as err:
                # key_error = True
                logger.warning(
                    "Could not find one of the files! Probably means the filename differs between original commit and backport commit"
                )
                logger.warning(str(err))
                # add the files anyway
                file[key] = ""
            # TODO(RobotSail): possibly add an ability to keep this / indicate failure in the dataset
            except UnicodeDecodeError:
                # decode_error = True
                logger.warning("Could not parse one of the files! Ignorning...")
                file[key] = ""
                continue

        files.append(file)
    return files


def _parse_multiple_upstream_backports(
    repo: UpstreamRepo,
    selected_languages: list[str]
    #    partials: bool
) -> ((int, int, int), list[dict]):
    matched = 0
    unmatched = 0
    multiples = 0
    cve_commits = 0
    bpdata = []
    bps = repo.find_backport_commits(selected_languages)
    if bps:
        for commit, ocommit, touched, renamed in bps:
            summary = (commit.message.splitlines() or [""])[0]
            out = ""
            if ocommit:
                matched += 1
                out = f"{repo.name} {commit.hex}: {summary} - backport of {ocommit}"
            else:
                unmatched += 1
                out = f"{repo.name} {commit.hex}: {summary} - backport of unknown"
            if 0 < len(touched):
                multiples += 1
                out += " - multiple-file Python code backport"
            print(out)
            if not ocommit or len(touched) == 0:
                continue
            is_cve_commit = repo.is_cve_commit(commit)
            cve_commits += 1 if is_cve_commit else 0
            ocommit = repo.pyrepo[ocommit]
            try:
                opatch = repo.patch_from_commit(ocommit, touched)
                bpatch = repo.patch_from_commit(commit, touched)
            except UnicodeDecodeError:
                logger.warning("Could not parse one of the patches! Ignoring...")
                continue
            if opatch == bpatch:
                continue
            obefore = repo.pyrepo.revparse_single(f"{ocommit.hex}^")
            bbefore = repo.pyrepo.revparse_single(f"{commit.hex}^")
            backport_renamed = repo.code_files_renamed(commit, selected_languages)
            upstream_renamed = repo.code_files_renamed(ocommit, selected_languages)
            affected_files = get_affected_files(
                repo,
                touched,
                obefore,
                ocommit,
                bbefore,
                commit,
                # include_partials,
            )
            bpdata.append(
                {
                    "upstream_commit_hash": ocommit.hex,
                    "upstream_commit_message": ocommit.message,
                    "upstream_patch": opatch,
                    "upstream_files_renamed": upstream_renamed,
                    "backport_commit_hash": commit.hex,
                    "backport_commit_message": commit.message,
                    "backport_patch": bpatch,
                    "affected_files": affected_files,
                    "backport_files_renamed": backport_renamed,
                    "files_touched": touched,
                    "is_cve_commit": is_cve_commit,
                    "cve_id": get_cve_id(commit.message),
                }
            )
    if bpdata:
        with open(
            f"{repo.clonedir}/{repo.name}-backports.json", "w", encoding="utf-8"
        ) as outfh:
            json.dump(bpdata, outfh, indent=4)
    return ((matched, unmatched, multiples, cve_commits), bpdata)


def _parse_upstream_backports(
    repo: UpstreamRepo, selected_languages: list[str]
) -> ((int, int, int, int), list[dict]):
    """
    Parse upstream backport commits for cmdline output (shared between
    subcommands).
    """
    matched = 0
    unmatched = 0
    singles = 0
    cve_commits = 0
    bpdata = []
    bps = repo.find_backport_commits(selected_languages)
    if bps:
        for commit, ocommit, touched in bps:
            summary = (commit.message.splitlines() or [""])[0]
            out = ""
            if ocommit:
                matched += 1
                out = f"{repo.name} {commit.hex}: {summary} - backport of {ocommit}"
            else:
                unmatched += 1
                out = f"{repo.name} {commit.hex}: {summary} - backport of unknown"
            if len(touched) == 1:
                singles += 1
                out += " - single-file Python code backport"
            print(out)
            if not ocommit or len(touched) != 1:
                continue
            is_cve_commit = repo.is_cve_commit(commit)
            cve_commits += 1 if is_cve_commit else 0
            ocommit = repo.pyrepo[ocommit]
            try:
                opatch = repo.patch_from_commit(ocommit, [touched[0]])
                bpatch = repo.patch_from_commit(commit, [touched[0]])
            except UnicodeDecodeError:
                logger.warning("Could not parse one of the patches! Ignoring...")
                continue
            if opatch == bpatch:
                continue
            obefore = repo.pyrepo.revparse_single(f"{ocommit.hex}^")
            bbefore = repo.pyrepo.revparse_single(f"{commit.hex}^")
            try:
                ubfile = repo.file_from_commit(obefore, touched[0])
                uafile = repo.file_from_commit(ocommit, touched[0])
                bbfile = repo.file_from_commit(bbefore, touched[0])
                bafile = repo.file_from_commit(commit, touched[0])
            except KeyError as err:
                logger.warning(
                    "Could not find one of the files! Probably means the filename differs between original commit and backport commit"
                )
                logger.warning(str(err))
                continue
            except UnicodeDecodeError:
                logger.warning("Could not parse one of the files! Ignorning...")
                continue
            renamed_files_upstream = repo.code_files_renamed(
                ocommit, selected_languages
            )
            renamed_files_backport = repo.code_files_renamed(commit, selected_languages)
            bpdata.append(
                {
                    "upstream_before": ubfile,
                    "upstream_commit_hash": ocommit.hex,
                    "upstream_commit_message": ocommit.message,
                    "upstream_patch": opatch,
                    "upstream_after": uafile,
                    "upstream_files_renamed": renamed_files_upstream,
                    "backport_before": bbfile,
                    "backport_commit_hash": commit.hex,
                    "backport_commit_message": commit.message,
                    "backport_patch": bpatch,
                    "backport_after": bafile,
                    "backport_files_renamed": renamed_files_backport,
                    "is_cve_commit": is_cve_commit,
                    "cve_id": get_cve_id(commit.message),
                }
            )
    if bpdata:
        with open(
            f"{repo.clonedir}/{repo.name}-backports.json", "w", encoding="utf-8"
        ) as outfh:
            json.dump(bpdata, outfh, indent=4)
    return (matched, unmatched, singles, cve_commits), bpdata


def _package_repo_sources(args):
    """
    Return the right package repo sources for the args (shared between
    subcommands).
    """
    sources = []
    if "fedora" in args.distros:
        sources.append(
            PagureRepoSource("fedora", "https://src.fedoraproject.org", "rpms")
        )
    if "centos" in args.distros:
        sources.append(PagureRepoSource("centos", "https://git.centos.org", "rpms"))
    if "cosstream" in args.distros:
        sources.append(GitlabRepoSource("cosstream", "https://gitlab.com", "8794173"))
    return sources


def package_cves(args):
    """Find CVE backports in distribution package repos."""
    foundcves = set()
    foundonep = set()
    foundonef = set()
    sources = _package_repo_sources(args)
    for source in sources:
        for repo in source.get_package_repos():
            for branch in repo.branches:
                try:
                    cves = [
                        commit.hex
                        for commit in repo.all_commits(branch)
                        if repo.is_cve_commit(commit)
                    ]
                except KeyError:
                    # just means the branch doesn't exist, that's OK
                    continue
                foundcves.update(cves)
                for cve in cves:
                    files = repo.files_created(cve)
                    if len(files) == 1:
                        foundonep.add(cve)
                        if repo.patch_modifies_one_file(cve, files[0]):
                            if cve not in foundonef:
                                print(f"Hit: {cve} in {source.name} {repo.name}!")
                            foundonef.add(cve)

    print(f"CVE commits found: {len(foundcves)}")
    print(f"CVE commits creating one file found: {len(foundonep)}")
    print(
        f"CVE commits creating one patch that modifies one file found: {len(foundonef)}"
    )


def tuple_from_backport(d: dict) -> tuple:
    """
    Accepts a dict representing a Backport object containing the following fields:
    - upstream_commit_hash
    - backport_commit_hash
    - upstream_commit_message
    - backport_commit_message
    - upstream_patch
    - backport_patch

    Returns a tuple with the above fields
    """
    return (
        d["upstream_commit_hash"],
        d["backport_commit_hash"],
        d["upstream_commit_message"],
        d["backport_commit_message"],
        d["upstream_patch"],
        d["backport_patch"],
    )


def remove_duplicates_from_backports(
    backports: dict[str, list[dict]]
) -> dict[str, list[dict]]:
    """
    Given a dataset of Backports across various repos,
    returns the same dataset with all duplicate values removed.
    """

    def remove_duplicates_from_list(l: list[dict]) -> list[dict]:
        """
        Accepts a list of Backports which have the following common features:
        - upstream_commit_hash
        - backport_commit_hash

        Returns a list with all duplicate backports removed
        """
        unique_bps = {}
        for bp in l:
            key = f"{bp['upstream_commit_hash']}:{bp['backport_commit_hash']}"
            if key not in unique_bps:
                unique_bps[key] = bp
            else:
                print(f"encountered duplicate backport: {key}")
        return list(unique_bps.values())

    return {repo: remove_duplicates_from_list(bps) for repo, bps in backports.items()}


def upstream_backports(args):
    """
    This finds upstream repos from the package source repos, where
    it can, then looks for backport commits in those upstream repos.
    """
    matched = 0
    unmatched = 0
    singles = 0
    multiples = 0
    cve_commits = 0
    sources = _package_repo_sources(args)
    backports = {}
    for source in sources:
        for urepo in source.get_upstream_repos():
            bpdata = []
            nmatched, nunmatched, nsingles, nmultiples, ncve_commits = 0, 0, 0, 0, 0
            if args.multiples:
                (
                    nmatched,
                    nunmatched,
                    nmultiples,
                    ncve_commits,
                ), bpdata = _parse_multiple_upstream_backports(
                    urepo,
                    args.languages
                    # args.partials,
                )
            else:
                (
                    nmatched,
                    nunmatched,
                    nsingles,
                    ncve_commits,
                ), bpdata = _parse_upstream_backports(urepo, args.languages)
            matched += nmatched
            unmatched += nunmatched
            singles += nsingles
            multiples += nmultiples
            cve_commits += ncve_commits
            backports[urepo] = bpdata
    print(f"Found {matched} backport commits with identifiable source commits!")
    print(f"Found {unmatched} backport commits without identifiable source commits!")
    print(f"Found {singles} single-file Python code backport commits!")
    print(f"Found {multiples} multiple-file Python code backport commits!")
    print(f'Found {cve_commits} backport commits with "CVE" in the commit message!')
    backports_without_duplicates = remove_duplicates_from_backports(backports)
    num_unique = sum(len(bps) for bps in backports_without_duplicates.values())
    total_bps = sum(len(bps) for bps in backports.values())
    print(f"Found {num_unique} unique backports out of {total_bps} total backports")
    print(f"Found {total_bps - num_unique} duplicate backports")
    with open(args.output, "w", encoding="utf-8") as outfh:
        json.dump(backports_without_duplicates, outfh, indent=4)


def investigate_duplicates(
    backports: dict[str, list[dict]]
) -> dict[list[tuple[str, dict]]]:
    # this function just goes through and collects all backport objects with matching upstream commit hashes
    # and outputs all of the ones with length over 1
    matching_backports = {}
    for repo, bps in backports.items():
        for bp in bps:
            upstream_hash = bp["upstream_commit_hash"]
            if upstream_hash not in matching_backports:
                matching_backports[upstream_hash] = []
            matching_backports[upstream_hash].append((repo, bp))

    return {k: v for k, v in matching_backports.items() if len(v) > 1}


def clean_backports(args):
    """
    Given a dataset of Backports, remove any duplicates and write
    the cleaned dataset to the output file.
    """
    with open(args.input, "r", encoding="utf-8") as infh:
        backports = json.load(infh)

    recurring_backports = investigate_duplicates(backports)
    offending_repos = set(
        repo for uh, bps in recurring_backports.items() for repo, bp in bps
    )
    print(f"Found {len(recurring_backports)} recurring backports")
    print(f'repos with recurring backports: {", ".join(offending_repos)}')
    with open("recurring.json", "w", encoding="utf-8") as outfh:
        json.dump(recurring_backports, outfh, indent=4)

    # for all of the recurring backports, group the repos together with the backports
    commonly_grouped_repos = set()
    for uh, bp_pairs in recurring_backports.items():
        # collect all offending repos
        repos = tuple([repo for repo, _ in bp_pairs])
        commonly_grouped_repos.add(repos)
    print(f"Found {len(commonly_grouped_repos)} groups of commonly grouped repos")
    print(
        f"commoonly grouped together repos:\n{json.dumps(list(commonly_grouped_repos), indent=4)})"
    )

    backports_without_duplicates = remove_duplicates_from_backports(backports)
    num_unique = sum(len(bps) for bps in backports_without_duplicates.values())
    total_bps = sum(len(bps) for bps in backports.values())
    print(f"Found {num_unique} unique backports out of {total_bps} total backports")
    print(f"Found {total_bps - num_unique} duplicate backports")

    if not args.dry_run:
        with open(args.output, "w", encoding="utf-8") as outfh:
            json.dump(backports_without_duplicates, outfh, indent=4)
        print(f"Cleaned backports written to {args.output}")


def sourcerepo_backports(args):
    """Find backport commits in upstream repo(s) specified by URL."""
    matched = 0
    unmatched = 0
    singles = 0
    multiples = 0
    cve_commits = 0
    backports = {}
    for i, url in enumerate(list(set(args.urls))):
        src = "cmdline"
        if "github.com" in url:
            src = "github"
        urepo = UpstreamRepo(url, src)
        bpdata = []
        nmatched, nunmatched, nmultiples, nsingles, ncve_commits = 0, 0, 0, 0, 0
        if args.multiples:
            (
                nmatched,
                nunmatched,
                nmultiples,
                ncve_commits,
            ), bpdata = _parse_multiple_upstream_backports(
                urepo,
                args.languages
                # args.partials,
            )
        else:
            (
                nmatched,
                nunmatched,
                nsingles,
                ncve_commits,
            ), bpdata = _parse_upstream_backports(urepo, args.languages)
        matched += nmatched
        unmatched += nunmatched
        singles += nsingles
        multiples += nmultiples
        cve_commits += ncve_commits
        backports[url] = bpdata
        print_progress_bar(
            i + 1, len(args.urls), prefix="Progress:", suffix="Complete", length=50
        )

    print(f"Found {matched} backport commits with identifiable source commits!")
    print(f"Found {unmatched} backport commits without identifiable source commits!")
    print(f"Found {singles} single-file Python code backport commits!")
    print(f"Found {multiples} multiple-file Python code backport commits!")
    print(f'Found {cve_commits} backport commits with "CVE" in the commit message!')
    backports_without_duplicates = remove_duplicates_from_backports(backports)
    num_unique = sum(len(bps) for bps in backports_without_duplicates.values())
    total_bps = sum(len(bps) for bps in backports.values())
    print(f"Found {num_unique} unique backports out of {total_bps} total backports")
    print(f"Found {total_bps - num_unique} duplicate backports")
    with open(args.output, "w", encoding="utf-8") as outfh:
        json.dump(backports_without_duplicates, outfh, indent=4)


def add_multiples_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-m",
        "--multiples",
        help="Whether or not the script should include multiple files that were patched",
        action="store_true",
    )


def add_languages_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-l",
        "--languages",
        help="The programming language(s) to include",
        metavar="language1 language2",
        nargs="+",
        choices=("python", "golang", "javascript", "java"),
        default=("python", "golang", "javascript", "java"),
    )


def add_outfile_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        help="The output file to write to",
        metavar="./workdir/output.json",
        default=f"{WORKDIR}/backports.json",
    )


def add_urls_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "urls",
        help="The git repo URL(s) to look in",
        metavar="https://github.com/foo/bar https://gitlab.com/beep/moo",
        nargs="+",
    )


def create_sourcerepo_backports_cmd(subparsers: argparse.ArgumentParser) -> None:
    parser_sourcerepo_backports = subparsers.add_parser(
        "sourcerepo-backports",
        description="Find backports in source repos specified by URL",
    )
    add_urls_arg(parser_sourcerepo_backports)
    add_multiples_arg(parser_sourcerepo_backports)
    add_languages_arg(parser_sourcerepo_backports)
    add_outfile_arg(parser_sourcerepo_backports)
    # parser_sourcerepo_backports.add_argument(
    #     "-p",
    #     "--partials",
    #     help="Whether or not the script should include datapoints where a file is missing from either the upstream or backport commit",
    #     action="store_true",
    # )
    parser_sourcerepo_backports.set_defaults(func=sourcerepo_backports)


def add_distros_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-d",
        "--distros",
        help="The distribution repo source(s) to look in",
        metavar="distro1 distro2",
        nargs="*",
        choices=("fedora", "centos", "cosstream"),
        default=("fedora", "centos", "cosstream"),
    )


def add_input_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-i",
        "--input",
        help="The input file to read from",
        metavar="./workdir/input.json",
    )


def add_dry_run_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dry-run",
        help="Whether or not to actually write the output file",
        action="store_true",
    )


def create_upstream_backports_cmd(subparsers: argparse.ArgumentParser) -> None:
    parser_upstream_backports = subparsers.add_parser(
        "upstream-backports",
        description="Find upstream repos from distro repos, then find backports in them",
    )
    add_distros_arg(parser_upstream_backports)
    add_multiples_arg(parser_upstream_backports)
    add_languages_arg(parser_upstream_backports)
    add_outfile_arg(parser_upstream_backports)
    parser_upstream_backports.set_defaults(func=upstream_backports)


def create_clean_backports_cmd(subparsers: argparse.ArgumentParser) -> None:
    parser_clean_backports = subparsers.add_parser(
        "clean-backports",
        description="Remove duplicate backports from a dataset",
    )
    add_input_arg(parser_clean_backports)
    add_outfile_arg(parser_clean_backports)
    add_dry_run_arg(parser_clean_backports)
    parser_clean_backports.set_defaults(func=clean_backports)


def create_package_cves_cmd(subparsers: argparse.ArgumentParser) -> None:
    parser_package_cves = subparsers.add_parser(
        "package-cves", description="Find CVE backports in distribution package repos"
    )
    add_distros_arg(parser_package_cves)
    parser_package_cves.set_defaults(func=package_cves)


def add_log_level_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-l",
        "--loglevel",
        help="The level of log messages to show",
        choices=("debug", "info", "warning", "error", "critical"),
        default="info",
    )


def parse_args():
    """Parse arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Script with various capabilities aimed at building a dataset "
            "for training AI models to do CVE backports."
        )
    )
    add_log_level_arg(parser)
    # https://github.com/python/cpython/issues/60512
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    create_package_cves_cmd(subparsers)
    create_upstream_backports_cmd(subparsers)
    create_sourcerepo_backports_cmd(subparsers)
    create_clean_backports_cmd(subparsers)
    args = parser.parse_args()
    return args


def main():
    """Main loop."""
    try:
        args = parse_args()
        loglevel = getattr(logging, args.loglevel.upper(), logging.INFO)
        logging.basicConfig(level=loglevel)
        args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted, exiting...\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
