#!/usr/bin/python

import json
import os
import subprocess

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

    def find_stable_branches(self):
        return []

    def checkout_spec(self, spec):
        ret = subprocess.run(["git", "checkout", spec], cwd=self.workdir, capture_output=True)
        return ret.returncode == 0

    def find_cve_commits(self):
        cves = []
        try:
            ret = subprocess.run(["git", "log", "--oneline"], cwd=self.workdir, capture_output=True, encoding="utf-8").stdout
        except UnicodeDecodeError:
            print("WARNING: could not parse changelog! Package ignored")
            return cves
        for line in ret.splitlines():
            (rev, desc) = line.split(maxsplit=1)
            if "cve" in desc.lower():
                cves.append(rev)
        return cves

    def files_created(self, rev):
        """Returns a tuple of filenames created by a given commit."""
        patch = subprocess.run(["git", "format-patch", "--stdout", f"{rev}~1..{rev}"], cwd=self.workdir, capture_output=True, encoding="utf-8").stdout
        patchfiles = []
        for line in patch.splitlines():
            if "create mode" in line:
                patchfiles.append(line.split()[-1])
        return patchfiles


class PackageRepo(Repo):
    def patch_modifies_one_file(self, rev, filename):
        """
        Given a commit rev and a filename, check out that commit,
        and - making an assumption that the file is a patch - check
        whether it modifies exactly one file.
        """
        if not self.checkout_spec(rev):
            print(f"WARNING: could not checkout {rev}!")
            return False
        try:
            with open(f"{self.workdir}/{filename}", "r", encoding="utf-8") as patchfh:
                patch = patchfh.read()
        except FileNotFoundError:
            print(f"WARNING: could not find patch file {filename}! Package ignored")
            return False
        print(f"Checking patch: {filename}")
        return patch.count("1 file changed") == 1

    @property
    def branches(self):
        if self.source == "fedora":
            return ("rawhide", "f36", "f37", "f38", "el6", "epel7", "epel8")
        elif self.source == "centos":
            return ("c9s", "c8s")


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


class FedoraRepoSource(PackageRepoSource):
    def __init__(self):
        super().__init__("fedora")
        self.apiurl = "https://src.fedoraproject.org/api/0/projects?namespace=rpms&pattern=python-*&owner=!orphan&short=true&fork=false&per_page=100"

    def repos_from_response(self, resp):
        return [f"https://src.fedoraproject.org/rpms/{project['name']}.git" for project in resp.json()["projects"]]

    def next_from_response(self, resp):
        return resp.json()["pagination"]["next"]


class CentOSRepoSource(PackageRepoSource):
    def __init__(self):
        super().__init__("centos")
        self.apiurl = "https://gitlab.com/api/v4/groups/8794173/projects?search=python-&archived=no&order_by=name&sort=asc&per_page=100"

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
for source in (FedoraRepoSource(), CentOSRepoSource()):
    repos = source.get_package_repos()
    for repo in repos:
        for branch in repo.branches:
            if not repo.checkout_spec(branch):
                # just means the branch doesn't exist, that's OK
                continue
            cves = repo.find_cve_commits()
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
