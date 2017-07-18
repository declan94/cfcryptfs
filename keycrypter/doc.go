/*
Package keycrypter provides two ways to safely store secret encryption keys.
	1) Password protection.
		Ask user for password and encrypt the key using the password before storing.
	2) Shamir's Secret Sharing
		Use Shamir's Secret Sharing algorithm to split the key into several parts and store in different places(media).
		All or a threshold count of the split keys are needed for reconstruct the key.
*/
package keycrypter
