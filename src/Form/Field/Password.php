<?php

namespace Encore\Admin\Form\Field;

class Password extends Text
{
    public function render()
    {
        $this->prepend('<i class="fa fa-eye-slash fa-fw"></i>')
            ->defaultAttribute('type', 'password')
            ->defaultAttribute('value', old($this->elementName ?: '', $this->value()));

        return parent::render();
    }
}
