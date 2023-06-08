#!/usr/bin/python

import argparse
import json
import logging
import os
import subprocess
import sys

import pygit2
import requests

# pylint:disable=invalid-name
logger = logging.getLogger(__name__)

WORKDIR = "/var/tmp/workdir"


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
            ret = subprocess.run(["git", "clone", self.url], cwd=self.clonedir, capture_output=True).returncode
            if ret:
                logger.warning("Clone of %s repo %s failed!", self.source, self.name)
        # init gitpython repo
        self.pyrepo = pygit2.Repository(self.workdir)

    def find_stable_branches(self):
        return []

    def checkout_spec(self, spec):
        try:
            self.pyrepo.checkout(spec)
            return True
        except pygit2.InvalidSpecError:
            # https://github.com/libgit2/pygit2/issues/1217
            ret = subprocess.run(["git", "checkout", spec], cwd=self.workdir, capture_output=True)
            return ret.returncode == 0


    def checkout_branch(self, branch):
        branch = self.pyrepo.branches[f"origin/{branch}"]
        return self.checkout_spec(branch)

    def is_cve_commit(self, commit, checkdiff=True):
        msg = commit.message
        if "Merge: " in msg:
            # merge commit
            return False
        if "cve-1" in msg.lower() or "cve-2" in msg.lower():
            return True
        if checkdiff:
            try:
                diff = self.pyrepo.diff(commit.parents[0], commit, context_lines=0).patch.lower()
            except IndexError:
                # probably the first commit
                return False
            except pygit2.GitError as err:
                # hmmm
                logger.warning("WARNING: unexpected pygit error in is_cve_commit for %s: %s %s! %s", self.source, self.name, commit.hex, str(err))
                return False
            except UnboundLocalError as err:
                # srsly wat
                logger.warning("WARNING: unexpected UnboundLocalError in is_cve_commit for %s: %s %s! %s", self.source, self.name, commit.hex, str(err))
                return False
            for line in diff.splitlines():
                if not line.startswith("-") and ("cve-1" in line or "cve-2" in line):
                    return True
        return False

    def all_commits(self, branch):
        if not branch.startswith("origin/"):
            branch = f"origin/{branch}"
        try:
            pybranch = self.pyrepo.branches[branch]
            last = self.pyrepo[pybranch.target]
            return self.pyrepo.walk(last.id, pygit2.GIT_SORT_TIME)
        except pygit2.GitError as err:
            logger.warning("WARNING: unexpected pygit error in all_commits for %s: %s! %s", self.source, self.name, str(err))
            return []

    def files_created(self, rev):
        """Returns a tuple of filenames created by a given commit."""
        pycommit = self.pyrepo.revparse_single(rev)
        patch = self.pyrepo.diff(pycommit.parents[0], pycommit).patch
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

    def find_backport_commits(self):
        """Find backport commits."""
        headlast = self.pyrepo[self.pyrepo.head.target].id
        # this is a bit icky but it lets us use a comprehension while
        # guarding against completely empty commit messages
        headcommits = [((commit.message.splitlines() or ["XXXNOCOMMITMSGFOUNDXXX"])[0], commit.hex) for commit in self.pyrepo.walk(headlast, pygit2.GIT_SORT_TIME)]
        backports = set()
        for branch in self.pyrepo.branches.remote:
            try:
                if self.pyrepo.branches[branch].is_head():
                    # we're looking for backports...
                    continue
                for commit in self.all_commits(branch):
                    if "backport of" in commit.message.lower():
                        summ = commit.message.splitlines()[0]
                        for (hsumm, hcomm) in headcommits:
                            # sometimes there are commits with summs
                            # like "Fix"...
                            if len(hsumm) > 15 and hsumm in summ:
                                if hcomm == commit.hex:
                                    # this is odd, but happens - there
                                    # are repos with commits on HEAD
                                    # which looks like backports, e.g.
                                    # github aio-libs/aiohttp 74e3d74
                                    continue
                                backports.add((commit.hex, summ, hcomm))
                        backports.add((commit.hex, summ, None))
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
            logger.warning("WARNING: could not checkout %s: %s %s!", self.source, self.name, rev)
            return False
        try:
            with open(f"{self.workdir}/{filename}", "r", encoding="utf-8") as patchfh:
                patch = patchfh.read()
        except FileNotFoundError:
            logger.warning("WARNING: could not find patch file %s in %s: %s %s! Package ignored", filename, self.source, self.name, rev)
            return False
        return patch.count("1 file changed") == 1

    def find_upstream_repo(self):
        """
        Try and find the upstream repo and return it as an instance if
        it's of a type we support.
        """
        try:
            if not self.checkout_branch(self.branches[0]):
                logger.warning("WARNING: could not checkout %s: %s %s!", self.source, self.name, self.branches[0])
        except KeyError:
            logger.warning("WARNING: could not find branch %s in %s: %s!", self.branches[0], self.source, self.name)
        if os.path.isfile(f"{self.workdir}/dead.package"):
            logger.debug("%s: %s %s branch is retired, ignored", self.source, self.name, self.branches[0])
            return None
        parsedspec = subprocess.run(["rpmspec", "--parse", f"{self.workdir}/{self.name}.spec"], cwd=self.workdir, encoding="utf-8", capture_output=True)
        if parsedspec.returncode:
            logger.warning("WARNING: could not parse spec file %s.spec in %s: %s! Package ignored", self.name, self.source, self.name)
            return None
        speclines = parsedspec.stdout.splitlines()
        for sline in speclines:
            if any(sline.lower().startswith(text) for text in ("url:", "source:", "source0:")):
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
                        logger.warning("WARNING: could not clone or initialize upstream repo %s for %s: %s", url, self.source, self.name)
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
        return [f"{self.baseurl}/{self.namespace}/{project['name']}.git" for project in resp.json()["projects"]]

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

def _parse_upstream_backports(repo):
    """
    Parse upstream backport commits for cmdline output (shared between
    subcommands).
    """
    matched = 0
    unmatched = 0
    bps = repo.find_backport_commits()
    if bps:
        for (commit, summary, ocommit) in bps:
            if ocommit:
                matched += 1
                print(f"{repo.name} {commit}: {summary} - backport of {ocommit}")
            else:
                unmatched += 1
                print(f"{repo.name} {commit}: {summary} - backport of unknown")
    return (matched, unmatched)

def _package_repo_sources(args):
    """
    Return the right package repo sources for the args (shared between
    subcommands).
    """
    sources = []
    if "fedora" in args.distros:
        sources.append(PagureRepoSource("fedora", "https://src.fedoraproject.org", "rpms"))
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
                    cves = [commit.hex for commit in repo.all_commits(branch) if repo.is_cve_commit(commit)]
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
    print(f"CVE commits creating one patch that modifies one file found: {len(foundonef)}")

def upstream_backports(args):
    """
    This finds upstream repos from the package source repos, where
    it can, then looks for backport commits in those upstream repos.
    """
    matched = 0
    unmatched = 0
    sources = _package_repo_sources(args)
    for source in sources:
        for urepo in source.get_upstream_repos():
            (nmatched, nunmatched) = _parse_upstream_backports(urepo)
            matched += nmatched
            unmatched += nunmatched
    print(f"Found {matched} backport commits with identifiable source commits!")
    print(f"Found {unmatched} backport commits without identifiable source commits!")

def sourcerepo_backports(args):
    """Find backport commits in upstream repo(s) specified by URL."""
    matched = 0
    unmatched = 0
    for url in args.urls:
        urepo = UpstreamRepo(url, "cmdline")
        (nmatched, nunmatched) = _parse_upstream_backports(urepo)
        matched += nmatched
        unmatched += nunmatched
    print(f"Found {matched} backport commits with identifiable source commits!")
    print(f"Found {unmatched} backport commits without identifiable source commits!")

def parse_args():
    """Parse arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Script with various capabilities aimed at building a dataset "
            "for training AI models to do CVE backports."
        )
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        help="The level of log messages to show",
        choices=("debug", "info", "warning", "error", "critical"),
        default="info",
    )
    # https://github.com/python/cpython/issues/60512
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    parser_package_cves = subparsers.add_parser(
        "package-cves",
        description="Find CVE backports in distribution package repos"
    )
    parser_package_cves.add_argument(
        "-d",
        "--distros",
        help="The distribution repo source(s) to look in",
        metavar="distro1 distro2",
        nargs="*",
        choices=("fedora", "centos", "cosstream"),
        default=("fedora", "centos", "cosstream")
    )
    parser_package_cves.set_defaults(func=package_cves)
    parser_upstream_backports = subparsers.add_parser(
        "upstream-backports",
        description="Find upstream repos from distro repos, then find backports in them"
    )
    parser_upstream_backports.add_argument(
        "-d",
        "--distros",
        help="The distribution repo source(s) to look in",
        metavar="distro1 distro2",
        nargs="*",
        choices=("fedora", "centos", "cosstream"),
        default=("fedora", "centos", "cosstream")
    )
    parser_upstream_backports.set_defaults(func=upstream_backports)
    parser_sourcerepo_backports = subparsers.add_parser(
        "sourcerepo-backports",
        description="Find backports in source repos specified by URL"
    )
    parser_sourcerepo_backports.add_argument(
        "urls",
        help="The git repo URL(s) to look in",
        metavar="https://github.com/foo/bar https://gitlab.com/beep/moo",
        nargs="+"
    )
    parser_sourcerepo_backports.set_defaults(func=sourcerepo_backports)

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

if __name__ == '__main__':
    main()
