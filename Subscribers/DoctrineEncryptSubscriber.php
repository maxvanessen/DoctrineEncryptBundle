<?php

namespace Ambta\DoctrineEncryptBundle\Subscribers;

use Doctrine\ORM\Event\OnFlushEventArgs;
use ReflectionClass;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Util\ClassUtils;
use Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Security\Core\Security;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    const ENCRYPTION_MARKER = '<ENC>';

    /**
     * Encryptor interface namespace
     */
    const ENCRYPTOR_INTERFACE_NS = 'Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'Ambta\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * Annotation reader
     * @var \Doctrine\Common\Annotations\Reader
     */
    private $annReader;

    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private $restoreEncryptor;

    /**
     * Count amount of decrypted values in this service
     * @var integer
     */
    public $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     * @var integer
     */
    public $encryptCounter = 0;

    private $security;

    /**
     * Initialization of subscriber
     *
     * @param Reader                  $annReader
     * @param string                  $encryptorClass The encryptor class.  This can be empty if a service is being provided.
     * @param EncryptorInterface|NULL $service        (Optional)  An EncryptorInterface.
     *
     * This allows for the use of dependency injection for the encrypters.
     */
    public function __construct(Reader $annReader, EncryptorInterface $encryptor, Security $security)
    {
        $this->annReader        = $annReader;
        $this->encryptor        = $encryptor;
        $this->restoreEncryptor = $this->encryptor;
        $this->security         = $security;
    }

    /**
     * Change the encryptor
     *
     * @param [type] $[name] [<description>]
     * @param EncryptorInterface $encryptorClass
     */
    public function setEncryptor(EncryptorInterface $encryptorClass)
    {
        $this->encryptor = $encryptorClass;
    }

    /**
     * Get the current encryptor
     *
     * @return Object returns the encryptor class or null
     */
    public function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor()
    {
        $this->encryptor = $this->restoreEncryptor;
    }

    /**
     * Listen a postUpdate lifecycle event.
     * Decrypt entities property's values when post updated.
     *
     * So for example after form submit the preUpdate encrypted the entity
     * We have to decrypt them before showing them again.
     *
     * @param LifecycleEventArgs $args
     */
    public function postUpdate(LifecycleEventArgs $args)
    {
        $entity = $args->getEntity();
        $this->processFields($entity, false);
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args)
    {
        $entity = $args->getEntity();
        $this->processFields($entity, false);
    }

    /**
     * Listen to onFlush event
     *
     * @param OnFlushEventArgs $preFlushEventArgs
     */
    public function onFlush(OnFlushEventArgs $args)
    {
        $unitOfWork = $args->getEntityManager()->getUnitOfWork();

        foreach ($unitOfWork->getScheduledEntityUpdates() as $entity) {
            $changeSet = $unitOfWork->getEntityChangeSet($entity);
            $this->processFields($entity, true, $changeSet);

            $classMetadata = $args->getEntityManager()->getClassMetadata(get_class($entity));
            $unitOfWork->recomputeSingleEntityChangeSet($classMetadata, $entity);
        }

        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $this->processFields($entity);

            $classMetadata = $args->getEntityManager()->getClassMetadata(get_class($entity));
            $unitOfWork->recomputeSingleEntityChangeSet($classMetadata, $entity);
        }
    }

    public function preUpdate(PreUpdateEventArgs $args)
    {
        $reflectionClass = new ReflectionClass($args->getEntity());
        $properties      = $reflectionClass->getProperties();

        foreach ($properties as $refProperty) {
            if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                $propName = $refProperty->getName();

                if ($args->hasChangedField($propName) === true) {
                    $oldValue = $args->getOldValue($propName);
                    $newValue = $args->getNewValue($propName);

                    dump($oldValue);
                    dump($newValue);

                    // The new value can still be encrypted
                    if (substr($newValue, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
                        // Decrypt it first
                        $newValue = $this->encryptor->decrypt($args->getEntity(), substr($newValue, 0, -5), $this->security->getUser());
                        dump($newValue);

                        $args->setNewValue($propName, $newValue);
                    }
                }
            }
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities that after inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs)
    {
        $unitOfWork = $postFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return Array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
    {
        return [
            Events::preUpdate,
            Events::postUpdate,
            Events::postLoad,
            Events::onFlush,
            Events::postFlush,
        ];
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object  $entity             doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @return object|null
     * @throws \RuntimeException
     *
     */
    public function processFields($entity, $isEncryptOperation = true, array $changeSet = [])
    {
        if (empty($this->encryptor)) {
            return $entity;
        }

        // Check which operation to be used
        $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';

        // Get the real class, we don't want to use the proxy classes
        if (strstr(get_class($entity), 'Proxies')) {
            $realClass = ClassUtils::getClass($entity);
        } else {
            $realClass = get_class($entity);
        }

        $properties = $this->getClassProperties($realClass);

        // Foreach property in the reflection class
        foreach ($properties as $refProperty) {
            if ($this->annReader->getPropertyAnnotation($refProperty, 'Doctrine\ORM\Mapping\Embedded')) {
                $this->handleEmbeddedAnnotation($entity, $refProperty, $isEncryptOperation);
                continue;
            }

            /**
             * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
             */
            if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                $propertyName = $refProperty->getName();

//                if (count($changeSet) === 0 || isset($changeSet[$propertyName]) === false) {
//                    continue;
//                }

                // Check for changes
//                dump($changeSet);
//
//                $propertyChangeSet = $changeSet[$propertyName];
//
//                $oldValue = $propertyChangeSet[0];
//                $newValue = $propertyChangeSet[1];
//
//                if (substr($oldValue, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
//                    // Decrypt it first
//                    $oldValue = $this->encryptor->decrypt($entity, substr($oldValue, 0, -5), $this->security->getUser());
//                }
//
//                if (substr($newValue, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
//                    // Decrypt it first
//                    $newValue = $this->encryptor->decrypt($entity, substr($newValue, 0, -5), $this->security->getUser());
//                }
//
//                if ($oldValue === $newValue) {
//                    continue;
//                }

                $pac   = PropertyAccess::createPropertyAccessor();
                $value = $pac->getValue($entity, $refProperty->getName());

                if ($encryptorMethod == 'decrypt') {
                    if (!is_null($value) and !empty($value)) {
                        if (substr($value, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
                            $this->decryptCounter++;
                            $currentPropValue = $this->encryptor->decrypt($entity, substr($value, 0, -5), $this->security->getUser());
                            $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                        }
                    }
                } else {
                    if (!is_null($value) and !empty($value)) {
                        if (substr($value, -strlen(self::ENCRYPTION_MARKER)) != self::ENCRYPTION_MARKER) {
                            $this->encryptCounter++;
                            $currentPropValue = $this->encryptor->encrypt($entity, $value, $this->security->getUser()).self::ENCRYPTION_MARKER;
                            $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                        }
                    }
                }
            }
        }

        return $entity;
    }

    private function handleEmbeddedAnnotation($entity, $embeddedProperty, $isEncryptOperation = true)
    {
        $reflectionClass = new ReflectionClass($entity);
        $propName        = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embeddedEntity = $pac->getValue($entity, $propName);

        if ($embeddedEntity) {
            $this->processFields($embeddedEntity, $isEncryptOperation);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     */
    private function getClassProperties($className)
    {
        $reflectionClass = new ReflectionClass($className);
        $properties      = $reflectionClass->getProperties();
        $propertiesArray = [];

        foreach ($properties as $property) {
            $propertyName                   = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }

        if ($parentClass = $reflectionClass->getParentClass()) {
            $parentPropertiesArray = $this->getClassProperties($parentClass->getName());
            if (count($parentPropertiesArray) > 0) {
                $propertiesArray = array_merge($parentPropertiesArray, $propertiesArray);
            }
        }

        return $propertiesArray;
    }
}
