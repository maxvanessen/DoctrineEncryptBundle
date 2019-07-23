<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

use AppBundle\Entity\Document;
use AppBundle\Entity\User;
use Doctrine\Common\Util\ClassUtils;
use \ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\HiddenString\HiddenString;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Class for encrypting and decrypting with the halite library
 */
class HaliteEncryptor implements EncryptorInterface
{
    private $encryptionKeys;
    private $keyFile;

    /**
     * {@inheritdoc}
     */
    public function __construct(string $keyFile)
    {
        $this->encryptionKeys = [];
        $this->keyFile        = $keyFile;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($entity, $data, User $user)
    {
        $document = $this->getDocument($entity);

        return Crypto::encrypt(new HiddenString($data), $this->getKey($document, $user));
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($entity, $data, User $user)
    {
        $document = $this->getDocument($entity);

        return Crypto::decrypt($data, $this->getKey($document, $user))->getString();
    }

    /**
     * @param Document $document
     *
     * @return \ParagonIE\Halite\Symmetric\EncryptionKey|null
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    private function getKey(Document $document, User $user)
    {
        if (isset($this->encryptionKeys[$document->getId()]) === false) {
            $encryptedKey = $document->getEncryptionKey();

            // Decrypt key
            $publicKey  = KeyFactory::importEncryptionPublicKey(new HiddenString($user->getPublicKey()));
            $privateKey = KeyFactory::loadEncryptionSecretKey('/Users/maxvanessen/www/menzis/review-review-api/my_secret_key');

            $decryptedKey = \ParagonIE\Halite\Asymmetric\Crypto::decrypt($encryptedKey, $privateKey, $publicKey);

            $this->encryptionKeys[$document->getId()] = KeyFactory::importEncryptionKey($decryptedKey);
        }

        return $this->encryptionKeys[$document->getId()];
    }

    private function getDocument($entity): Document
    {
        // Get the real class, we don't want to use the proxy classes
        if (strstr(get_class($entity), 'Proxies')) {
            $className = ClassUtils::getClass($entity);
        } else {
            $className = get_class($entity);
        }

        if ($className === Document::class) {
            return $entity;
        } else {
            $pac = PropertyAccess::createPropertyAccessor();

            return $pac->getValue($entity, 'document');
        }
    }
}
