# Deployment playbooks for NGI-Pipeline and related software (Piper, TACA, Tarzan, etc.)

This repository concerns the creation and maintenance of the NGI python environment; which is a collection of software and solutions utilized by NGI Production on the currently available HPC. The solutions in question are unique for NGI Production and require updates to such a degree that deploying them within the facility is preferred.
The NGI environment is currently deployed on Irma using Ansible playbooks. Ansible playbooks are scripts written for easily adaptable automated deployment. The Ansible playbooks are stored here.

## Bootstrap the Ansible environment

Before any deployments can be done we need to setup the Ansible environment. If we've got a clean environment then this can be done by running the bootstrap script:

```
newgrp ngi-sw
curl -L https://raw.githubusercontent.com/NationalGenomicsInfrastructure/irma-provision/master/bootstrap/bootstrap.sh -o /tmp/bootstrap.sh
bash /tmp/bootstrap.sh
```

It is recommended that the user adds the following two lines (or something similar) into `~/.bashrc`:

```
alias irmaenv='source /lupus/ngi/irma3/bashrc'
alias ansibleenv='source /lupus/ngi/irma3/ansible-env/bin/activate'
```

## User prerequisites before developing or deploying

Before a user starts developing new Ansible playbooks/roles or deploy them, the current umask and GID needs to be set, and the Ansible virtual environment needs to be loaded.

This can be accomplished by *manually* running the two bash aliases defined above: `irmaenv` followed by `ansibleenv`.  

Note that the order is important, and that they should not be run automatically at login, because that will cause an infinite loop that will lock out the user from `irma3`.

Also note that the `NouGAT` role sometimes has problems running, and may require you to load the `boost` module prior to usage.

## Simple environment integrity verification

Once the ansible-playbook has successfully been executed, log onto the target machine.

Run `source /lupus/ngi/conf/sourceme_<SITE>.sh` where `<SITE>` is `upps` to initialize `funk_004` variables, or `sthlm` to initialize `funk_006` variables.

Run `source activate NGI` to start the environment.

`python NGI_pipeline_test.py create --fastq1 <R1.fastq.gz> --fastq2 <R2.fastq.gz> --FC 1` creates a simulated flowcell.

Run `ngi_pipeline_start.py` with the commands `organize flowcell`, `analyze project` and `qc project` to organize, analyze and qc the generated data respectively.

## Deployment of the NGI pipeline

### Requirements
The following files need to be present on irma3 in order to successfully deploy a working version of NGI pipeline:

- A working connection to charon or charon-dev as well as a generated API token.

- A valid GATK key placed under `/lupus/ngi/irma3/deploy/files`. The filename must be specified in the `gatk_key` variable in `host_vars/127.0.0.1/main.yml`.

- A `charon_credentials.yml` file placed under `/lupus/ngi/irma3/deploy/host_vars/127.0.0.1/` listing the variables `charon_base_url_{stage,prod}`, `charon_api_token_upps_{stage,prod}` and `charon_api_token_sthlm_{stage,prod}`

- A valid `statusdb_creds_{stage,prod}.yml` access file placed under `/lupus/ngi/irma3/deploy/files`. Necessary layout is described at https://github.com/SciLifeLab/statusdb

- A valid `orderportal_credentials.yml` access file placed under `/lupus/ngi/irma3/deploy/files`.

- Valid SSL certificates for the web proxy under `/lupus/ngi/irma3/deploy/files` (see `roles/tarzan/README.md` for details)

### Typical development and staging deployments

Typically roles are developed (or at least tested) locally on `irma3`.

Start by forking the repository https://github.com/NationalGenomicsInfrastructure/irma-provision to your private Github repo. Then clone this private repository to `/lupus/ngi/irma3/devel`. Inside there you can develop your own Ansible roles in your private feature branch. Note that the git repository does not include the required `files` subdirectory (see above). This directory can be created manually or copied from an existing setup.

If you want to test your roles/playbook run `ansible-playbook install.yml`. This will install your development run in `/lupus/ngi/irma3/devel-root/<username>_<branch_name>`.

When you are satisfied with your changes you need to test it in staging. To do this, you must create a pull request to one of the two staging branches of irma-provision.

There are two staging branches in the repository, one called monthly and the other bimonthly. The changes that do not need extensive testing and validation on stage should be pushed to the monthly branch, which is used to make stage and production deployments on a monthly cycle. Changes that need time for validation on stage (like pipeline version updates) should be pushed to the bimonthly branch.

Production deployments on the monthly release cycle are done on the last Monday of each month. A stage deployment from the monthly branch will be made two weeks before this date and the introduction of new changes to the monthly branch will be frozen. Only fixes to changes already merged will be approved to the monthly branch during this time.

Stage deployments from the bimonthly branch can be made outside of the monthly release cycle. The changes on the bimonthly branch would generally be pulled to the monthly branch and deployed to production in the monthly release cycle once all validations are complete.

Do the following once the feature has been approved. The deployment version should be `$(date +%y%m%d).$(git rev-parse --short HEAD)-bimonthly` in case of the bimonthly branch.

```
    cd /lupus/ngi/irma3/deploy
    git checkout [monthly/bimonthly]
    git pull origin [monthly/bimonthly]
    ansible-playbook install.yml -e deployment_environment=staging -e deployment_version=$(date +%y%m%d).$(git rev-parse --short HEAD)
    python sync.py -e staging -d deployment_version
```

This will install your run under `/lupus/ngi/staging/$(date +%y%m%d).$(git rev-parse --short HEAD)` and symlink `/lupus/ngi/staging/latest` to it, for easier access. The `sync.py` script also has an option to perform a dry run of the files that will be synced before the actual sync takes place.

If you want to stage test many feature branches at the same time then an alternative is to create a pre-release of the master branch at Github (https://github.com/NationalGenomicsInfrastructure/irma-provision/releases/new), and then running the `ansible-playbook` command after having checkout the corresponding pre-release tag (similar to how it is done for production deployments). Make sure to write a good release note so it is clear what significant things are included.

When everything is synced over to Irma properly then login to e.g. `irma1` as your personal user and run `source /lupus/ngi/staging/latest/conf/sourceme_<site>.sh && source activate NGI` (where `site` is `upps` or `sthlm` depending on location). For convenience add this to your personal file bash init file `~/.bashrc`. This will load the staging environment for your user with the appropriate staging variables set.

When the staged environment has been verified to work OK (TODO: add test protocol, manual or automated sanity checks) proceed with making a pull request from the staging branch to the master branch of the repository. Once your pull request is approved and merged, create a production release at https://github.com/NationalGenomicsInfrastructure/irma-provision/releases/new. Make sure to write a good release note that summarizes all the significant changes that are included since the last production release.

##### Arteria staging

The Arteria roles will pick up on whether we're running in `deployment_environment` equal to `production` or `staging` and then use different ports, runfolders, log files, etc.

So in essence it should work almost as usual. You run something similar to:

```
ansible-playbook install.yml -e deployment_environment=staging -e deployment_version=arteria-staging-FOO -e arteria_checksum_version=660a8ff
python sync.py -e staging
```

if you want to stage test a specific commit hash of `arteria-checksum` and the default versions of the other arteria services.

Launch the Arteria staging services by running the command `start-arteria-staging` as the `funk_004` user. That will spawn a detached screen session named `arteria-staging` with one window for each Arteria web service. If a service has crashed then one can (after debugging the stacktrace) respawn the process by hitting the `r` key  for the relevant window. If one want to manually force a restart of the process one can first abort the process with a normal `^C`, followed by the `r` key as mentioned previously. To kill all Arteria services the whole screen session can be closed down with the command `stop-arteria-staging`.  

### Typical production deployments

A typical deployment of a production environment to Irma consists of the following steps

- Running through the Ansible playbook for a production release, which will install all the software under `/lupus/ngi/production/<version>` (and create a symlink `/lupus/ngi/production/latest` pointing to it)
- Syncing everything under `/lupus/ngi/production` to the cluster
- Reload *each site's* crontabs and services

To install software and sync to the cluster, run the following commands:

```
   cd /lupus/ngi/irma3/deploy
   git checkout master
   git fetch --tags
   git checkout tags/vX.Y
   ansible-playbook install.yml -e deployment_environment=production
   python sync.py -e production -d vX.Y
```

This will install and sync over the Irma environment version `vX.Y`.

To see all available production releases go to https://github.com/NationalGenomicsInfrastructure/irma-provision/releases

#### Reload crontabs and services

Remember that you will probably have to restart services manually after a new production release have been rolled out. This must be done for *each site*. First re-load the crontab as the func user on `irma1` with a `crontab /lupus/ngi/production/latest/conf/crontab_SITE`. Then, depending on what software your func user is running, continue with manually shutting down the old versions and re-start the new versions of the software. In the case of Uppsala one should then do a `/lupus/ngi/production/latest/resources/stop_kong.sh` followed by starting `supervisord` and `kong` (see the crontab).  


## Manual initializations on irma1

Run `crontab /lupus/ngi/<instance>/<version>/conf/crontab_<site>` once per user to initialize the first instance of cron for the user. As mentioned above, this has to be done for each new production release.

Run `/lupus/ngi/<instance>/<version>/resources/create_ngi_pipeline_dirs.sh <project_name>` once per project (i.e. ngi2016003) to create the log, db and softlink directories for NGI pipeline (and generate the softlinks).

Add `source /lupus/ngi/<instance>/<version>/conf/sourcme_<site>.sh && source activate NGI`, where `site` can be `upps` or `sthlm`, to each functional account's bash init file `~/.bashrc`.

## Other worthwhile information

Deploying requires the deployer to be in both the `ngi-sw` and the `ngi` groups. Everything under `/lupus/ngi/` is owned by `ngi-sw`.

Only deployers can write new programs and configs, but all NGI functional accounts (`funk_004`, `funk_006` etc) can write log files, to the SQL databases, etc.

Global configuration values are set in the repository under `host_vars/127.0.0.1/main.yml`, and each respective role's in the `<role>/defaults/main.yml` file.

The log `/lupus/ngi/irma3/log/ansible.log` logs the files installed by Ansible.

The log `/lupus/ngi/irma3/log/rsync.log` logs the rsync history.

When developing roles deployed directories must have the setgid flag `g+s`, and be created while the deployer had his gid set to `ngi-sw`. This ensures the files in the dirs recieve the correct group owner when they are created. This will be taken care of the user always sources the file `/lupus/ngi/irma3/bashrc` before doing any work.
