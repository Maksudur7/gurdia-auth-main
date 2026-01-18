// src/common/guards/policy.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PolicyEngine } from '../../auth/policies/policy.handler.js';

@Injectable()
export class PolicyGuard implements CanActivate {

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const user = request.user;

        console.log('request is ', request);

        if (!user) return false;
        const targetId = request.body?.resourceId || request.params?.id;
        const resource = targetId ? { userId: targetId } : null;
        const isAllowed = PolicyEngine.evaluate({
            user,
            resource,
            action: request.method === 'GET' ? 'read' : 'write',
        });
        if (!isAllowed) {
            throw new ForbiddenException('Policy Violation: Access Denied due to account status or ownership.');
        }
        return true;
    }
}