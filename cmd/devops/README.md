


## Building


### Compiling locally 

In order to build devops, you will need (packr)[https://github.com/gobuffalo/packr] to include the Golang files from the 
example [build/cicd](https://gitlab.com/geeks-accelerator/oss/devops/tree/master/build/cicd)


This repo has a pre-commit hook at `.git/hooks/post-commit` to detect changes to `build/cicd` tool.
```bash
#!/bin/sh
#

# update files for cmd/devops with packr 
devopsDir=$(git rev-parse --show-toplevel)/cmd/devops
echo "updating pack files for cmd/devops"
curDir=$PWD
cd $devopsDir 

packr2 

cd $curDir 

git add cmd/devops/packrd

fileChanged=$(git diff cmd/devops/packrd)
if [[ $fileChanged != "" ]]; then
	git add cmd/devops/packrd/*
	git commit --amend -C HEAD  --no-verify
fi 
```

