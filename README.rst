Wsu Crypt
==========

WsuCrypt is implemented using java. It supports both 64bit and 80bit keys.


How to run
~~~~~~~~~~

The code is available in the ``src`` folder.
For convenience I have created a jar in the ``lib`` folder.

Encryption
~~~~~~~~~~

To encrypt make sure to provide a ``key.txt`` and ``plaintext.txt`` file inside the ``lib`` folder.
A sample has been provided for you. An assumption is made that the ``key.txt`` file exists and its in hex and
that the ``plaintext.txt`` file exists and its in ASCII. The program will crash if this files are missing.
Run the following command to encrypt the file.

.. code-block:: bash

    $ java -jar wsucrypt.jar encrypt

Upon completion a ``ciphertext.txt`` file will be created.

Decryption
~~~~~~~~~~

To decrypt make sure to provide a ``key.txt`` and ``ciphertext.txt`` file inside the ``lib`` folder.
A sample has been provided for you. An assumption is made that the ``key.txt`` file exists and its in hex and
that the ``ciphertext.txt`` file existsand its in hex. The program will crash if this files are missing.
Run the following command to decrypt the file.

.. code-block:: bash

    $ java -jar wsucrypt.jar encrypt

Upon completion a ``plaintext.txt`` file will be created.
