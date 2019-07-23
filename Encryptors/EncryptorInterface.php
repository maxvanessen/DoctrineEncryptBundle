<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

use AppBundle\Entity\User;

/**
 * Encryptor interface for encryptors
 *
 * @author Victor Melnik <melnikvictorl@gmail.com>
 */
interface EncryptorInterface
{

    /**
     * @param string $keyFile Path where to find and store the keyfile
     */
    public function __construct(string $keyFile);

    /**
     * @param object $entity
     * @param string $data Plain text to encrypt
     * @return string Encrypted text
     */
    public function encrypt($entity, $data, User $user);

    /**
     * @param object $entity
     * @param string $data Encrypted text
     * @return string Plain text
     */
    public function decrypt($entity, $data, User $user);
}
