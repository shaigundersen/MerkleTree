"""
Made by Shai Gundersen as part of homework as a Computer science student at Bar-Ilan University

"""
import hashlib

import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64



class Node:
    def __init__(self, data=None):
        if data is None:
            self.__value = ''
        else:
            m = hashlib.sha256()
            m.update(data.encode())
            self.__value = m.hexdigest()
        self.__parent = None
        self.__left = None
        self.__right = None
        self.__childHasChanged = True


    @property
    def childChanged(self):
        return self.__childHasChanged
    @childChanged.setter
    def childChanged(self, data):
        self.__childHasChanged = data

    @property
    def value(self):
        return self.__value
    @value.setter
    def value(self, data):
        self.__value = data

    @property
    def right(self):
        return self.__right
    @right.setter
    def right(self, node):
        self.__right = node
        self.__childHasChanged = True

    @property
    def left(self):
        return self.__left
    @left.setter
    def left(self, node):
        self.__left = node
        self.__childHasChanged = True

    @property
    def parent(self):
        return self.__parent
    @parent.setter
    def parent(self, node):
        self.__parent = node


class MerkleTree:
    def __init__(self):
        self.__root = Node()
        self.__lastLeaf = None
        self.__size = 0

    def add_leaf(self, data):
        leaf = Node(data)
        if self.__lastLeaf is None:  # this is the first leaf of the tree
            parent = Node()
            leaf.parent = parent
            parent.left = leaf
            self.__root = parent
            self.__root.value = rec_calc_node(self.__root)
        else:
            if self.__lastLeaf.parent.right is None:
                parent = self.__lastLeaf.parent
                parent.right = leaf
                leaf.parent = parent
                # update value of parent to be hash of both children
                parent.value = rec_calc_node(parent)
            else:
                connectiveParent = self.__lastLeaf.parent
                count = 1
                # walk up the tree
                while (connectiveParent.parent is not None) and (connectiveParent.right is not None):
                    connectiveParent = connectiveParent.parent
                    count += 1
                leafParent = Node()
                # while loop ended cause we got to root -> make a new root
                if connectiveParent.parent is None:
                    newRoot = Node()
                    newRoot.left = connectiveParent
                    connectiveParent.parent = newRoot
                    newRoot.right = leafParent
                    leafParent.parent = newRoot
                    self.__root = newRoot
                # while loop ended cause we got to a node with no right child
                else:
                    connectiveParent.right = leafParent
                    leafParent.parent = connectiveParent
                    count -= 1
                # walk down the tree and construct it's children
                while count > 1:
                    child = Node()
                    leafParent.left = child
                    child.parent = leafParent
                    leafParent = child
                    count -= 1
                leafParent.left = leaf
                leaf.parent = leafParent

            parent = leaf.parent
            # inform all nodes along the way to root that this child has changed
            while parent is not None:
                parent.childChanged = True
                parent = parent.parent
        self.__lastLeaf = leaf
        self.__size += 1

    def calc_root(self):
        self.__root.value = rec_calc_node(self.__root)
        return self.__root.value

    def create_proof_of_inclusion(self, num):
        # tree index is a 1's base, but num is of 0's base
        num += 1
        # no leaf with index num
        if num > self.__size:
            return
        hashRoot = self.calc_root()
        proof = []
        node = self.__root
        halfSize = self.__size
        if halfSize % 2 == 0:
            halfSize //= 2
        else:
            halfSize //= 2
            halfSize += 1
        power = 1
        while power < self.__size:
            power *= 2
        # keep going if not leaf
        while power >= 1:
            power //= 2
            if num <= power:
                value = rec_calc_node(node.right)
                if value is not None:
                    # 1 to indicate this has to be hashed from the right
                    value = "1"+value
                node = node.left
            else:
                value = rec_calc_node(node.left)
                if value is not None:
                    # 0 to indicate this has to be hashed from the left
                    value = "0" + value
                node = node.right
                num -= power
            if value is not None:
                # proof.append(value)
                proof.insert(0,value)

        toReturn = hashRoot
        for val in proof:
            toReturn += " " + val
        return toReturn
    @property
    def root(self):
        return self.__root

    @staticmethod
    def check_inclusion(data, proofOfInclusion):
        if proofOfInclusion is None:
            return False
        splitted = proofOfInclusion.split(' ')
        m = hashlib.sha256()
        m.update(data.encode())
        digest = m.hexdigest()

        for i in range(1, len(splitted)):
            m = hashlib.sha256()
            # check indicator, 0 -> cat as leftchild, 1-> as right
            if splitted[i][0] == "0":
                cat = splitted[i][1:]+digest
            elif splitted[i][0] == "1":
                cat = digest+splitted[i][1:]
            else:  # no indicator
                return False
            m.update(cat.encode())
            digest = m.hexdigest()

        if digest == splitted[0]:
            return True
        return False

    def creat_keys(self):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pemSK = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        publicKey = privateKey.public_key()
        pemPK = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pemSK, pemPK

    def sign_root(self, pemSK):
        root = self.calc_root().encode()
        sk = load_pem_private_key(pemSK, None, default_backend())
        signature = base64.b64encode(
            sk.sign(
                root,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        )
        return signature

    @staticmethod
    def check_signature(pemPK, signature, massage):
        signature = base64.b64decode(signature.encode())
        pk = load_pem_public_key(pemPK, default_backend())
        try:
            pk.verify(
                signature,
                massage.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

def rec_calc_node(node):
    # check valid
    if node is None:
        return None
    # base case - if node is a leaf OR already evaluated return it's value
    if (node.left is None and node.right is None) or node.childChanged is False:
        return node.value
    else:
        m = hashlib.sha256()
        leftSide = ""
        rightSide = ""
        value = ""
        if node.left is not None:
            leftSide = rec_calc_node(node.left)
        if node.right is not None:
            rightSide = rec_calc_node(node.right)
            concat = leftSide + rightSide
            m.update(concat.encode())
            # update value of node to be hash of both children
            value = m.hexdigest()
        else:
            # if no right child then val of parent is simply left child and NOT hash of left child
            value = leftSide
        # update node along the way
        node.value = value
        # to indicate that we have evaluated this node for next time
        node.childChanged = False
        return value

# converts a string to binary. default is hex to bin
def to_bin(digest, scale=16, numOfBits=256):
    return bin(int(digest, scale))[2:].zfill(numOfBits)

def main_loop():
    while True:
        userInput = input().split(" ")
        if userInput[0] == "1":  # add new leaf
            tree.add_leaf(userInput[1])
        elif userInput[0] == "2":  # get root
            print(tree.calc_root())
        elif userInput[0] == "3":  # create proof of inclusion to node number X
            print(tree.create_proof_of_inclusion(int(userInput[1])))
        elif userInput[0] == "4":  # check proof of inclusion
            prof = userInput[2]
            for i in range(3, len(userInput)):
                prof = prof + " " + userInput[i]
            print(MerkleTree.check_inclusion(userInput[1], prof))
        elif userInput[0] == "5":  # create keys
            keys= tree.creat_keys()
            print(keys[0].decode()+'\n'+keys[1].decode())
        elif userInput[0] == "6":  # sign root
            # expect to get input with many lines
            cat = ''
            for i in range(1, len(userInput)):
                cat = cat + userInput[i] + ' '
            cat = cat[:-1]
            secrete_key = cat+'\n'
            line = ''
            while True:
                line = input()
                if len(line) > 0:
                    line = line + '\n'
                    secrete_key += line
                else:
                    break
            print(tree.sign_root(secrete_key.encode()).decode())

        elif userInput[0] == "7":  # verify signature
            # expect to get input with many lines
            cat = ''
            for i in range(1, len(userInput)):
                cat = cat + userInput[i] + ' '
            cat = cat[:-1]
            public_key = cat + '\n'
            line = ''
            while True:
                line = input()
                if len(line) > 0:
                    line = line + '\n'
                    public_key += line
                else:
                    break
            signature, msg = input().split(" ")
            print(MerkleTree.check_signature(public_key.encode(), signature, msg))

        elif userInput[0] == "8":  # change value of leaf
            smt.change_val(userInput[1])
        elif userInput[0] == "9":  # get root
            print(smt.get_root())
        elif userInput[0] == "10":  # creat proof of inclusion
            print(smt.create_proof_of_inclusion(userInput[1]))
        elif userInput[0] == "11":  # check proof
            prof = userInput[3]
            for i in range(4, len(userInput)):
                prof = prof + " " + userInput[i]
            print(SMT.check_inclusion(userInput[1], userInput[2], prof))


class SMT:
    # calc default values for each layer and hold as a static member
    defaultLevelValues = ["0"]
    def __init__(self, n):
        self.dept = n
        # map(parent) -> (LeftChild , RightChild) ## not including last layer == leaf
        # first map is a default one
        self.levelMap = {}
        child = SMT.defaultLevelValues[0]
        for i in range(self.dept):
            m = hashlib.sha256()
            m.update((child + child).encode())
            parent = m.hexdigest()
            SMT.defaultLevelValues.insert(0, parent)
            self.levelMap[parent] = (child, child)
            child = parent
        self.root = child

    def get_root(self):
        return self.root

    def change_val(self, digest):
        # convert to binary
        digest_as_bin_string = to_bin(digest)
        brothers = []
        # start from root and path down to find the matching child
        # save all brothers along the way so we know which nodes we need to change when pathing up
        # then path up and change brothers&parents accordingly
        node = self.root
        for i in range(self.dept):
            if digest_as_bin_string[i] == '1':
                leftBrother = self.levelMap[node][0]
                brothers.append(leftBrother)
                node = self.levelMap[node][1]
            else:
                rightBrother = self.levelMap[node][1]
                brothers.append(rightBrother)
                node = self.levelMap[node][0]

        # we got to the leaf
        node = '1'
        # now we path up, so we have to start from last index to the first
        for i in range(self.dept-1, -1, -1):
            m = hashlib.sha256()
            # it means we got here because we took a right turn, so hash node as right child
            if digest_as_bin_string[i] == '1':
                concat = brothers[i] + node
                m.update(concat.encode())
                parent = m.hexdigest()
                self.levelMap[parent] = (brothers[i], node)
            else:
                concat = node + brothers[i]
                m.update(concat.encode())
                parent = m.hexdigest()
                self.levelMap[parent] = (node, brothers[i])
            node = parent
        # update root
        self.root = node

    def create_proof_of_inclusion(self, digest):
        digest_as_bin_string = to_bin(digest)
        proof = []
        node = self.root
        for i in range(self.dept):
            # if we got to a default value, we dont need the rest of children under
            if node == SMT.defaultLevelValues[i]:
                proof.append(node)
                break
            if digest_as_bin_string[i] == '1':
                leftBrother = self.levelMap[node][0]
                proof.append(leftBrother)
                node = self.levelMap[node][1]
            else:
                rightBrother = self.levelMap[node][1]
                proof.append(rightBrother)
                node = self.levelMap[node][0]

        toReturn = self.root
        # prof is from leaf to root so reverse
        proof.reverse()
        for prof in proof:
            toReturn += " " + prof
        return toReturn

    @staticmethod
    def check_inclusion(digest, classification, proofOfInclusion):
        if proofOfInclusion is None:
            return False
        splitted = proofOfInclusion.split(' ')
        # remove first element
        proof_root = splitted.pop(0)
        # convert to binary
        digest_as_bin_string = to_bin(digest)
        if len(splitted) > len(digest_as_bin_string):
            return False
        elif len(splitted) == len(digest_as_bin_string):
            j = len(splitted)-1
        else:
            j = len(splitted)-2

        # prof is from leaf to root so reverse
        splitted.reverse()
        node = classification
        # path up
        # i runs on digest.reversed | j runs on splitted.reversed
        for i in range(len(digest_as_bin_string)-1, -1, -1):
            m = hashlib.sha256()
            # digest len > proof len , use default values
            if i > j:
                if digest_as_bin_string[i] == '1':
                    # i+1 because default vals has 257 layers (including base leaf
                    concat = SMT.defaultLevelValues[i + 1] + node
                else:
                    concat = node + SMT.defaultLevelValues[i + 1]
            else:
                if digest_as_bin_string[i] == '1':
                    concat = splitted[j] + node
                else:
                    concat = node + splitted[j]
                j -= 1
            m.update(concat.encode())
            # just for clarification
            parent = m.hexdigest()
            node = parent

        return proof_root == node


smt = SMT(256)
tree = MerkleTree()

if __name__ == '__main__':
    # main_loop()
    print(smt.get_root())
    dig='0'*64
    smt.change_val(dig)
    dig2='f'*64
    # smt.change_val(dig2)
    # profB=smt.create_proof_of_inclusion(dig2)
    # print(profB)
    print(smt.check_inclusion(dig2, '0', "9ca619dd4a13d02391aeb48fa9dd0a56f6fcf7ed0bc7311c45e64c052eca7133 1ba915e042e9aafcd4348b060345025ef2eb8f93d4fc7fe1719b9a7e1c1034be 451f7cb426ffa960fdad0301d4f4ccf4107751dfbe878cc5a71824f72b4d67bc"))
    # print(smt.check_inclusion(dig2, '1', "9ca619dd4a13d02391aeb48fa9dd0a56f6fcf7ed0bc7311c45e64c052eca7133 1ba915e042e9aafcd4348b060345025ef2eb8f93d4fc7fe1719b9a7e1c1034be 451f7cb426ffa960fdad0301d4f4ccf4107751dfbe878cc5a71824f72b4d67bc"))





