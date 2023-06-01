#!/usr/bin/python

import json
import os
import subprocess

import pygit2
import requests

WORKDIR = "/var/tmp/workdir"


class Repo:
    def __init__(self, url, source):
        self.url = url
        self.source = source
        # "https://github.com/psf/requests.git" -> "requests"
        self.name = url.split("/")[-1][:-4]
        self.clonedir = f"{WORKDIR}/{source}"
        self.workdir = f"{self.clonedir}/{self.name}"
        if not os.path.exists(self.clonedir):
            os.makedirs(self.clonedir)
        if not os.path.exists(self.workdir):
            subprocess.run(["git", "clone", self.url], cwd=self.clonedir, capture_output=True)
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
                print(f"WARNING: unexpected pygit error in is_cve_commit for {self.source}: {self.name} {commit}! {str(err)}")
                return False
            except UnboundLocalError:
                # srsly wat
                print(f"WARNING: unexpected UnboundLocalError in is_cve_commit for {self.source}: {self.name} {commit}! {str(err)}")
                return False
            for line in diff.splitlines():
                if not line.startswith("-") and ("cve-1" in line or "cve-2" in line):
                    print(f"Found CVE commit {commit.hex} in {self.name}!")
                    return True
        return False

    def all_commits(self, branch):
        pybranch = self.pyrepo.branches[f"origin/{branch}"]
        last = self.pyrepo[pybranch.target]
        try:
            return list(self.pyrepo.walk(last.id, pygit2.GIT_SORT_TIME))
        except pygit2.GitError:
            print(f"WARNING: unexpected pygit error in is_cve_commit for {self.source}: {self.name} {commit}! {str(err)}")
            return False

    def find_cve_commits(self):
        cves = []
        try:
            ret = subprocess.run(["git", "log", "--oneline"], cwd=self.workdir, capture_output=True, encoding="utf-8").stdout
        except UnicodeDecodeError:
            print(f"WARNING: could not parse changelog! {self.source}: {self.name} ignored")
            return cves
        for line in ret.splitlines():
            (rev, desc) = line.split(maxsplit=1)
            if "cve" in desc.lower():
                cves.append(rev)
        return cves

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


class PackageRepo(Repo):
    def patch_modifies_one_file(self, rev, filename):
        """
        Given a commit rev and a filename, check out that commit,
        and - making an assumption that the file is a patch - check
        whether it modifies exactly one file.
        """
        if not self.checkout_spec(rev):
            print(f"WARNING: could not checkout {self.source}: {self.name} {rev}!")
            return False
        try:
            with open(f"{self.workdir}/{filename}", "r", encoding="utf-8") as patchfh:
                patch = patchfh.read()
        except FileNotFoundError:
            print(f"WARNING: could not find patch file {filename} in {self.source}: {self.name} {rev}! Package ignored")
            return False
        print(f"Checking patch: {filename}")
        return patch.count("1 file changed") == 1

    @property
    def branches(self):
        if self.source == "fedora":
            return ("rawhide", "f36", "f37", "f38", "el6", "epel7", "epel8")
        elif self.source == "cosstream":
            return ("c9s", "c8s")
        elif self.source == "centos":
            return ("c4", "c5", "c6", "c7")


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
        return [PackageRepo(repo, self.name) for repo in repos]


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

foundcves = set()
foundonep = set()
foundonef = set()
sources = (
    PagureRepoSource("fedora", "https://src.fedoraproject.org", "rpms"),
    PagureRepoSource("centos", "https://git.centos.org", "rpms"),
    GitlabRepoSource("cosstream", "https://gitlab.com", "8794173")
)
for source in sources:
    repos = source.get_package_repos()
    for repo in repos:
        for branch in repo.branches:
            #cves = repo.find_cve_commits()
            try:
                cves = [commit.hex for commit in repo.all_commits(branch)[:-1] if repo.is_cve_commit(commit)]
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
