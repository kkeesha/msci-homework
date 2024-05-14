import httpx
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel
import asyncio
from itertools import chain

class VulnerablePackage(BaseModel):
    name: str
    versions: list[str]
    timestamp: str

class Package(BaseModel):
    name: str
    ecosystem: str

class VulnerableVersionsRequest(BaseModel):
    package: Package

app = FastAPI()


@app.get("/versions")
async def get_vulnerable_versions(name: str):
    vulnerable_debian_package_request = VulnerableVersionsRequest(package=Package(name=name, ecosystem='Debian'))
    vulnerable_ubuntu_package_request = VulnerableVersionsRequest(package=Package(name=name, ecosystem='Ubuntu'))

    async with httpx.AsyncClient() as client:
        debian_res, ubuntu_res = await asyncio.gather(client.post('https://api.osv.dev/v1/query', json=vulnerable_debian_package_request.model_dump()), 
                                                      client.post('https://api.osv.dev/v1/query', json=vulnerable_ubuntu_package_request.model_dump()))

    debian_versions = get_versions_debian(debian_res)
    ubuntu_versions = get_versions_ubuntu(ubuntu_res, name)
    all_versions = sorted(debian_versions.union(ubuntu_versions))
    now = datetime.now()

    return VulnerablePackage(name=name, timestamp=now.strftime("%Y-%m-%d %H:%M:%S"), versions=all_versions)

def get_versions_debian(package_res) -> set[str]:
    affected_packages = [vuln['affected'] for vuln in package_res.json().get('vulns', [])]
    versions_partitions = [package.get('versions', []) for package in flatten(affected_packages)]
    versions = flatten(versions_partitions)
    return set(versions)

def get_versions_ubuntu(package_res, name) -> set[str]:
    affected_packages = [vuln['affected'] for vuln in package_res.json().get('vulns', [])]
    ecosystem_specifics = [ecosystem.get('ecosystem_specific', []) for ecosystem in flatten(affected_packages)]
    binaries = [binary.get('binaries', []) for binary in ecosystem_specifics]
    versions_partitions = [package_version.get(name, []) for package_version in flatten(binaries)]
    versions = flatten(versions_partitions)
    return set(versions)

def flatten(list_of_lists: list[list]):
    result = []
    for partition in list_of_lists:
        if isinstance(partition, list):
            for item in partition:
                result.append(item)
        else:
            result.append(partition)
    return result
