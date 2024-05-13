import httpx
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel

class VulnerablePackage(BaseModel):
    name: str
    versions: list[str]
    timestamp: datetime

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
        debian_res = await client.post('https://api.osv.dev/v1/query', json=vulnerable_debian_package_request.model_dump())
        ubuntu_res = await client.post('https://api.osv.dev/v1/query', json=vulnerable_ubuntu_package_request.model_dump())

    debian_versions = get_versions(debian_res)
    ubuntu_versions = get_versions(ubuntu_res)
    all_versions = sorted(debian_versions.union(ubuntu_versions))
    return VulnerablePackage(name=name, timestamp=datetime.now(), versions=all_versions)

def get_versions(debian_res) -> set[str]:
    affected_packages = [vuln['affected'] for vuln in debian_res.json().get('vulns', [])]
    versions_partitions = [package.get('versions', []) for package in flatten(affected_packages)]
    versions = flatten(versions_partitions)
    return set(versions)

#TODO better name for 'j'
def flatten(list):
    return [
    j
    for partition in list
    for j in partition
]