
AWS ECS service logs are collected via a Lambda function. This lambda which triggers on Cloudwatch log group events 
forwards the logs to Datadog.

To start collecting logs from your AWS ECS services:

1. Set up this Datadog lambda function

2. [Enable logging](https://docs.datadoghq.com/integrations/amazon_web_services/?tab=allpermissions#enable-logging-for-your-aws-service) 
for your AWS service (most AWS services can log to a S3 bucket or CloudWatch Log Group).

3. Configure the triggers that cause the lambda to execute. There are two ways to configure the triggers:
    - [automatically](https://docs.datadoghq.com/integrations/amazon_web_services/?tab=allpermissions#automatically-setup-triggers): 
    Datadog automatically retrieves the logs for the selected AWS services and adds them as triggers on the Datadog Lambda function. Datadog also keeps the list up to date.
    - [manually](https://docs.datadoghq.com/integrations/amazon_web_services/?tab=allpermissions#manually-setup-triggers): 
    Set up each trigger yourself via the AWS console.
    
Refer to Datadogs documentation on [log collection](https://docs.datadoghq.com/integrations/amazon_web_services/?tab=allpermissions#log-collection) 
for more information about about shipping logs to Datadog from AWS.
