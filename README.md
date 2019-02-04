# Computer Science 445 – Capstone Sprint 2019


| Branch  | Status |
| ------------- | ------------- |
| Develop  | TODO  |
| Master  | TODO |



**Authors**
- Igor Mekhtiev

# Installation Instructions


## Vagrant installation

- Install  [Vagrant](https://www.vagrantup.com/downloads.html)
- Ensure that [VirtualBox](http://www.oracle.com/technetwork/server-storage/virtualbox/downloads/index.html) or your favorite virtualization software is installed.

## Starting up Vagrant box

From the `<project root>/vagrant` directory and run:
#### On windows run the command line as an Administrator

```
vagrant plugin install vagrant-cachier
vagrant plugin install vagrant-faster
vagrant box update
vagrant up
vagrant ssh
```

From vagrant machine
```
cd ~/source
ls -lah
```

## To test tensorflow installation

```
vagrant ssh
python3 -c "import tensorflow as tf; tf.enable_eager_execution(); print(tf.reduce_sum(tf.random_normal([1000, 1000])))"
```

## Shut down Vagrant box

From the `<project root>/vagrant` directory and run:
```
vagrant halt
```

## To destroy vagrant box and free up space

From the `<project root>/vagrant` directory and run:
```
vagrant destroy
```


# Change log since last sprint

* Created vagrant box
