package: dep
	rm -rf pkg/centos_installer ; mkdir pkg/centos_installer
	for I in centos_installer/*.py; do ln -snf "../../$$I" pkg/centos_installer/; done
	python3 -m zipapp --output centos-installer.pyz --python '/usr/bin/env python3' -m centos_installer:main $(PWD)/pkg

dep: pkg/.canary

pkg/.canary:
	rm -rf pkg
	mkdir pkg
	pip3 install --target "$(PWD)/pkg" -r requirements.txt
	touch pkg/.canary

clean:
	rm -rf pkg centos-installer.pyz
