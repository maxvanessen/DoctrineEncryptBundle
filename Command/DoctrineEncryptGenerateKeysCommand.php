<?php

namespace Ambta\DoctrineEncryptBundle\Command;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Get status of doctrine encrypt bundle and the database.
 *
 * @author Marcel van Nuil <marcel@ambta.com>
 * @author Michael Feinbier <michael@feinbier.net>
 */
class DoctrineEncryptGenerateKeysCommand extends AbstractCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('doctrine:encrypt:generate')
            ->setDescription('Generate new public/private key pair');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $sign_keypair = \ParagonIE\Halite\KeyFactory::generateSignatureKeyPair();
        $sign_secret = $sign_keypair->getSecretKey();
        $sign_public = $sign_keypair->getPublicKey();

        $file = 'public.key';

        $output->writeln('Saving public key... ');

        \ParagonIE\Halite\KeyFactory::save($sign_public, $file);
        \ParagonIE\Halite\KeyFactory::save($sign_secret, 'private.key');

        $output->writeln('');
    }
}
