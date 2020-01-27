# Solve the error when install Keystone-engine
# error: Setup script exited with error: 
#    can't copy 'src\build\llvm\lib\libkeystone.so': 
#       doesn't exist or not a regular file

git clone https://github.com/keystone-engine/keystone.git
cd keystone/bindings/python/
python3 setup.py install    # python3 can be changed to another python path even venv
