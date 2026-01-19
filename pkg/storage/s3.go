package storage

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"stream.api/internal/config"
)

type Provider interface {
	GeneratePresignedURL(key string, expire time.Duration) (string, error)
	Delete(key string) error
}

type s3Provider struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	bucket        string
}

func NewS3Provider(cfg *config.Config) (Provider, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(
		context.TODO(),
		awsconfig.WithRegion(cfg.AWS.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AWS.AccessKey, cfg.AWS.SecretKey, "")),
	)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.AWS.ForcePathStyle
		if cfg.AWS.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.AWS.Endpoint)
		}
	})

	return &s3Provider{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		bucket:        cfg.AWS.Bucket,
	}, nil
}

func (s *s3Provider) GeneratePresignedURL(key string, expire time.Duration) (string, error) {
	req, err := s.presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, func(o *s3.PresignOptions) {
		o.Expires = expire
	})

	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (s *s3Provider) Delete(key string) error {
	_, err := s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	return err
}
