# findskus

CLI tool for finding Azure SKUs and regions meeting certain criteria.

## Motivation

The two commands available in the Azure CLI do not have enough functionality to
analyze which regions are suffering from degragations or lack of support for
various features.

Additionally, `az vm list-skus` takes between 15 seconds to 2 minutes to execute
per region. The only way to analyze its outputs without going insane is to put
store the output in a JSON and do analysis.

The goal of this tool is to be able to quickly find the most healthy,
well-suited region based on SKU criteria for the workload that you want to run.

## Security consideration

This tool uses `az vm list-skus` and `az account locations`.

Obviously I trust this tool since I wrote it myself. But you should really not
trust tools like these to run on your own infra.

> [!WARNING]
> It is highly recommended that you create a SP with Reader access to the
> Subscription and run the tool in an isolated environment.

## Pre-requisites

- Access to `/tmp`
- Azure CLI (`az` in the path)
- Azure CLI logged in (`az login`)

## Installation

For now, only installable with Go:

```bash
go install github.com/sebnyberg/findskus@latest
```

## Usage

> [!IMPORTANT]
> On the first run, locations will be (slowly) downloaded from azure to a
> directory in `/tmp`. To view progress, run in verbose mode with `-v`.

### Finding SKUs

Find SKUs with 16GB RAM in West Europe:

```bash
findskus --min-memory 16 --max-memory 16 --encryption-at-host -l westeurope
```

Find SKUs in any region with at least 64 vCPUs that are available for use:

```bash
findskus --min-vcpu 64
```

Find all SKUs with accelerated networking in southcentralus or westus, output as
JSON.

```bash
findskus --accelerated-networking -l southcentralus,westus -o json
```

### Listing location statistics

To view location statistics, add `--by-location`:

```bash
findskus --min-memory 16 --max-memory 16 --encryption-at-host --by-location
```

Find locations that has premium IO in at least two availability zones:

```bash
findskus --premium-io --min-zones 2 --by-location
```

### Re-downloading skus

After changing the subscription, you should re-download Azure data with:
`--redownload`:

```bash
findskus --redownload [...]
```
